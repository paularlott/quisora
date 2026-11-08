package sqlstore

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/paularlott/gossip/hlc"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"
)

// The tables beside the kind tables; docs/DATABASE.md describes every table. No name is a reserved word of any of
// the databases, so none needs quoting, here or in an operator's own query.
const (
	uniqueTable = "unique_values"
	feedTable   = "store_identity" // one row: the store's id (feed_id), new after a restore
	schemaTable = "schema_version"
)

// tableNames is the table of each kind. They are named for what they hold, not after the kind (which is also in the
// backup format and the BadgerDB keys, and so stays as it is). Keep docs/DATABASE.md in step.
var tableNames = map[model.Kind]string{
	model.KindOrg:            "organizations",
	model.KindUser:           "users",
	model.KindGroup:          "user_groups", // GROUPS is reserved in MySQL 8
	model.KindMember:         "group_members",
	model.KindTenant:         "tenants",
	model.KindAccess:         "tenant_access",
	model.KindClient:         "clients",
	model.KindProvider:       "identity_providers",
	model.KindPasskey:        "passkeys",
	model.KindIdentity:       "linked_identities",
	model.KindSession:        "sessions",
	model.KindGrant:          "refresh_grants",
	model.KindConsent:        "app_consents",
	model.KindAPIToken:       "api_tokens",
	model.KindKey:            "signing_keys",
	model.KindSSHKey:         "ssh_ca_keys",
	model.KindSSHCert:        "ssh_certificates",
	model.KindAudit:          "audit_events",
	model.KindLink:           "link_tokens",
	model.KindSignIn:         "sign_ins",
	model.KindOrgLogo:        "organization_logos",
	model.KindEmailTemplates: "email_templates",
	model.KindLock:           "leases",
	model.KindReplay:         "single_use_values",
	model.KindEphemeral:      "ephemeral_state",
	model.KindQueue:          "retry_queue",
}

// tableName is the (unquoted) table of a kind.
func tableName(kind model.Kind) string {
	n, ok := tableNames[kind]
	if !ok {
		panic("sqlstore: no table name for kind " + string(kind))
	}
	return n
}

// table holds the generated SQL for one kind. Statements use ? placeholders already rewritten for the dialect.
type table struct {
	kind   model.Kind
	name   string // quoted table name
	fields []model.Field
	cols   string // every column, in scan order

	get      string // WHERE id = ? and live
	lookup   string // WHERE id = ?, whatever the state
	byUnique string // WHERE id is the holder of a unique value (kind, value) and live
	meta     string // version, origin, deleted, expires, uniq, epoch, created_v, req of one id, row-locked
	shared   string // meta, the row share-locked (a transaction's assertion)
	insert   string
	update   string

	uInsert, uHolder, uSteal string // unique-table statements for this kind

	aboveSQL  string // one record of one partition with a sequence above ?, if there is one (ExportPartition)
	exportSQL string // a page of the records of one partition with a sequence above ? and at most ?, after (sequence ?, id ?), in that order (ExportPartition)
	tombSQL   string // version and sequence of the tombstones of one partition with a sequence above ? and at most ? (PartitionTombstones)
	goneSQL   string // id and kind-less metadata of the records of one partition (full import, purge)
}

// partColumns are the columns every kind table has beyond the record's first ones: part is store.Record.Partition and
// req is store.Record.Req (the request that wrote the record; "" on a row written before the column existed), both read
// with the record; pnum and pseq stamp a record ApplyPartition or ImportPartition wrote (the partition and the sequence
// of the write that last changed it; pseq 0: no stamp), written with it, and read only by the partition methods. A
// table made before they existed gains them at open (reconcile).
func partColumns(d *dialect) []struct{ name, def string } {
	return []struct{ name, def string }{
		{"part", d.keyType(512) + " NOT NULL DEFAULT ''"},
		{"req", d.keyType(64) + " NOT NULL DEFAULT ''"},
		{"pnum", "INT NOT NULL DEFAULT 0"},
		{"pseq", "BIGINT NOT NULL DEFAULT 0"},
	}
}

func newTable(d *dialect, kind model.Kind) *table {
	s := model.Schemas[kind]
	t := &table{kind: kind, name: d.quote(tableName(kind)), fields: s.Fields}
	cols := []string{"id", "version", "origin", "deleted", "scope", "expires", "uniq", "data", "epoch", "created_v", "part", "req"}
	for _, f := range s.Fields {
		cols = append(cols, f.Name)
	}
	q := make([]string, len(cols))
	for i, c := range cols {
		q[i] = d.quote(c)
	}
	t.cols = strings.Join(q, ", ")
	// A write sets the partition stamp too (pnum, pseq), which a read does not return.
	cols = append(cols, "pnum", "pseq")
	q = append(q, d.quote("pnum"), d.quote("pseq"))
	wcols := strings.Join(q, ", ")
	marks := strings.TrimSuffix(strings.Repeat("?, ", len(cols)), ", ")
	t.get = d.bind("SELECT " + t.cols + " FROM " + t.name + " WHERE id = ? AND deleted = FALSE AND (expires IS NULL OR expires > ?)")
	// A scalar subquery, not a join: SQLite re-prepares a joined statement at every step (6x slower than the two lookups).
	t.byUnique = d.bind("SELECT " + t.cols + " FROM " + t.name + " WHERE id = (SELECT id FROM " + uniqueTable +
		" WHERE kind = ? AND value = ?) AND deleted = FALSE AND (expires IS NULL OR expires > ?)")
	metaSQL := "SELECT version, origin, deleted, expires, uniq, epoch, created_v, req, part FROM " + t.name + " WHERE id = ?"
	t.meta = d.bind(metaSQL + d.lockClause(""))
	t.shared = d.bind(metaSQL + d.shareClause())
	t.lookup = d.bind("SELECT " + t.cols + " FROM " + t.name + " WHERE id = ?")
	t.insert = d.bind("INSERT INTO " + t.name + " (" + wcols + ") VALUES (" + marks + ")")
	// Every partition read says pseq > 0 although its bound sequence (never negative) implies it: SQLite uses the partial
	// index on (pnum, pseq) only for a WHERE clause that implies the index's, and pseq > ? does that only when bound to 0.
	t.exportSQL = d.bind("SELECT " + t.cols + ", pseq FROM " + t.name + " WHERE pnum = ? AND pseq > 0 AND pseq > ? AND pseq <= ? " +
		"AND (pseq > ? OR (pseq = ? AND id > ?)) ORDER BY pseq, id LIMIT " + strconv.Itoa(batchRows))
	t.aboveSQL = d.bind("SELECT 1 FROM " + t.name + " WHERE pnum = ? AND pseq > 0 AND pseq > ? LIMIT 1")
	t.tombSQL = d.bind("SELECT version, pseq FROM " + t.name + " WHERE pnum = ? AND pseq > 0 AND pseq > ? AND pseq <= ? AND deleted = TRUE")
	t.goneSQL = d.bind("SELECT id, deleted, pseq FROM " + t.name + " WHERE pnum = ? AND pseq > 0")
	sets := make([]string, 0, len(cols)-1)
	for _, c := range q[1:] {
		sets = append(sets, c+" = ?")
	}
	t.update = d.bind("UPDATE " + t.name + " SET " + strings.Join(sets, ", ") + " WHERE id = ?")
	t.uInsert = d.bind(d.insertIgnore(uniqueTable, "kind, value, id", "?, ?, ?"))
	t.uHolder = d.bind("SELECT u.id, k.version, k.deleted, k.expires FROM " + uniqueTable + " u LEFT JOIN " + t.name +
		" k ON k.id = u.id WHERE u.kind = ? AND u.value = ?" + d.lockClause("u"))
	t.uSteal = d.bind("UPDATE " + uniqueTable + " SET id = ? WHERE kind = ? AND value = ? AND id = ?")
	return t
}

// micros converts a time to unix microseconds; the zero time is 0.
func micros(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.UnixMicro()
}

func fromMicros(v int64) time.Time {
	if v == 0 {
		return time.Time{}
	}
	return time.UnixMicro(v).UTC()
}

// fieldArg converts a field value to its column value. A nil value is the type's zero value.
func fieldArg(f model.Field, v any) (any, error) {
	switch f.Type {
	case model.FieldString:
		switch x := v.(type) {
		case nil:
			return "", nil
		case string:
			return x, nil
		}
	case model.FieldBool:
		switch x := v.(type) {
		case nil:
			return false, nil
		case bool:
			return x, nil
		}
	case model.FieldInt:
		switch x := v.(type) {
		case nil:
			return int64(0), nil
		case int:
			return int64(x), nil
		case int32:
			return int64(x), nil
		case int64:
			return x, nil
		case uint32:
			return int64(x), nil
		case uint64:
			return int64(x), nil
		}
	case model.FieldTime:
		switch x := v.(type) {
		case nil:
			return int64(0), nil
		case time.Time:
			return micros(x), nil
		}
	}
	return nil, fmt.Errorf("field %q: unsupported value %T", f.Name, v)
}

func encodeUnique(u []string) any {
	if len(u) == 0 {
		return nil
	}
	b, _ := json.Marshal(u)
	return string(b)
}

func decodeUnique(s sql.NullString) ([]string, error) {
	if !s.Valid || s.String == "" {
		return nil, nil
	}
	var u []string
	if err := json.Unmarshal([]byte(s.String), &u); err != nil {
		return nil, fmt.Errorf("sqlstore: decode unique values: %w", err)
	}
	return u, nil
}

func blobArg(b []byte) any {
	if b == nil {
		return nil
	}
	return b
}

// pstamp is the partition stamp of a written record (zero: none).
type pstamp struct {
	num  int
	pseq int64
}

// args returns the column values of rec in insert order. Tombstones carry no scope, data, fields or expiry (and keep
// their partition key).
func (t *table) args(rec *store.Record, ps pstamp) ([]any, error) {
	a := make([]any, 0, 15+len(t.fields))
	var expires any
	scope := rec.Scope
	if rec.Deleted {
		scope = ""
	} else if !rec.Expires.IsZero() {
		expires = rec.Expires.UnixMicro()
	}
	var uniq any
	var data []byte
	var created int64
	epoch := int64(rec.Epoch) // kept on a tombstone too
	if !rec.Deleted {
		uniq, data, created = encodeUnique(rec.Unique), rec.Data, int64(rec.Created)
	}
	a = append(a, rec.ID, int64(rec.Version), rec.Origin, rec.Deleted, scope, expires, uniq, blobArg(data), epoch, created,
		rec.Partition, rec.Req)
	for _, f := range t.fields {
		var v any
		if !rec.Deleted {
			v = rec.Fields[f.Name]
		}
		fa, err := fieldArg(f, v)
		if err != nil {
			return nil, err
		}
		a = append(a, fa)
	}
	return append(a, ps.num, ps.pseq), nil
}

type scanner interface{ Scan(dest ...any) error }

// scan reads a row selected with t.cols.
func (t *table) scan(r scanner) (*store.Record, error) {
	var (
		id, origin, scope, part, req string
		version                      int64
		epoch, created               int64
		deleted                      bool
		expires                      sql.NullInt64
		uniq                         sql.NullString
		data                         []byte
	)
	dest := []any{&id, &version, &origin, &deleted, &scope, &expires, &uniq, &data, &epoch, &created, &part, &req}
	vals := make([]any, len(t.fields))
	for i, f := range t.fields {
		switch f.Type {
		case model.FieldString:
			vals[i] = new(string)
		case model.FieldBool:
			vals[i] = new(bool)
		default:
			vals[i] = new(int64)
		}
	}
	dest = append(dest, vals...)
	if err := r.Scan(dest...); err != nil {
		return nil, err
	}
	unique, err := decodeUnique(uniq)
	if err != nil {
		return nil, err
	}
	rec := &store.Record{Kind: t.kind, ID: id, Version: hlc.Timestamp(version), Origin: origin, Deleted: deleted,
		Scope: scope, Partition: part, Req: req, Unique: unique, Data: data, Epoch: hlc.Timestamp(epoch),
		Created: hlc.Timestamp(created)}
	// Several nodes may write one database; their versions come from their own clocks. A version read here moves
	// this node's clock past it, so its next write of the record is newer even when its wall clock is behind.
	store.Witness(rec.Version)
	if expires.Valid {
		rec.Expires = time.UnixMicro(expires.Int64).UTC()
	}
	if !deleted {
		rec.Fields = make(map[string]any, len(t.fields))
		for i, f := range t.fields {
			switch v := vals[i].(type) {
			case *string:
				rec.Fields[f.Name] = *v
			case *bool:
				rec.Fields[f.Name] = *v
			case *int64:
				if f.Type == model.FieldTime {
					rec.Fields[f.Name] = fromMicros(*v)
				} else {
					rec.Fields[f.Name] = *v
				}
			}
		}
	}
	return rec, nil
}

// ddl returns the statements that create the table and its indexes.
func (t *table) ddl(d *dialect) []string {
	cols := []string{
		"id " + d.keyType(191) + " NOT NULL PRIMARY KEY",
		"version BIGINT NOT NULL",
		"origin " + d.keyType(128) + " NOT NULL DEFAULT ''",
		"deleted BOOLEAN NOT NULL DEFAULT FALSE",
		"scope " + d.keyType(191) + " NOT NULL DEFAULT ''",
		"expires BIGINT NULL",
		"uniq " + d.textType() + " NULL",
		"data " + d.blobType() + " NULL",
		"epoch BIGINT NOT NULL DEFAULT 0",     // store.Record.Epoch
		"created_v BIGINT NOT NULL DEFAULT 0", // store.Record.Created
	}
	for _, c := range partColumns(d) {
		cols = append(cols, c.name+" "+c.def)
	}
	for _, f := range t.fields {
		cols = append(cols, d.quote(f.Name)+" "+d.colType(f))
	}
	create := "CREATE TABLE IF NOT EXISTS " + t.name + " (\n  " + strings.Join(cols, ",\n  ") + "\n)"
	if d.isMySQL() {
		create += " ENGINE=InnoDB DEFAULT CHARSET=utf8mb4" + d.strCollate()
	}
	out := []string{create}
	idx := func(name, keys string) {
		out = append(out, fmt.Sprintf("CREATE INDEX %s%s ON %s (%s)", ifNotExists(d), d.quote("ix_"+tableName(t.kind)+"_"+name), t.name, keys))
	}
	if !model.Unscoped(t.kind) { // the records of an unscoped kind all have the empty scope: nothing to find by it
		idx("scope", "scope, id")
	}
	// The purge of the expired (read.go) is the one reader of this index, and a kind that never expires is not purged
	// of them. Where the database has partial indexes, a kind that only sometimes has an expiry (the members of a
	// group, mostly kept) indexes just the records that carry one.
	switch e := model.ExpiryOf(t.kind); {
	case e == model.NeverExpires:
	case e == model.MayExpire && !d.isMySQL():
		out = append(out, fmt.Sprintf("CREATE INDEX IF NOT EXISTS %s ON %s (expires) WHERE expires IS NOT NULL",
			d.quote("ix_"+tableName(t.kind)+"_expires"), t.name))
	default:
		idx("expires", "expires")
	}
	if d.isMySQL() { // the partition sequence index (ExportPartition, a full import, PurgePartition)
		idx("part", "pnum, pseq")
	} else { // partial: only the records a partition write stamped
		out = append(out, fmt.Sprintf("CREATE INDEX IF NOT EXISTS %s ON %s (pnum, pseq) WHERE pseq > 0",
			d.quote("ix_"+tableName(t.kind)+"_part"), t.name))
	}
	if d.isMySQL() { // the tombstones of a partition by sequence (PartitionTombstones, PurgePartition)
		idx("parttomb", "pnum, deleted, pseq")
	} else {
		out = append(out, fmt.Sprintf("CREATE INDEX IF NOT EXISTS %s ON %s (pnum, pseq) WHERE deleted = TRUE AND pseq > 0",
			d.quote("ix_"+tableName(t.kind)+"_parttomb"), t.name))
	}
	if d.isMySQL() {
		idx("tomb", "deleted, version")
	} else { // partial: the planner must never pick it for the (far more common) deleted = FALSE queries
		// Nor does a partition's tombstone (stamped: it has the index above) need it: Purge leaves those to their partition.
		out = append(out, fmt.Sprintf("CREATE INDEX IF NOT EXISTS %s ON %s (version) WHERE deleted = TRUE AND pseq = 0",
			d.quote("ix_"+tableName(t.kind)+"_tomb"), t.name))
	}
	for _, f := range t.fields {
		if f.Sort {
			if e := d.sortIndexExpr(f); e != "" {
				idx("s_"+f.Name, "scope, "+e+", id")
				// Newest first is how a large kind's times are browsed (the audit log's default page): SQLite and PostgreSQL
				// read the index above backwards and sort only the ties, but MySQL and MariaDB cannot (the tie-break by id
				// stays ascending) and sort the whole scope: 7x slower on 60,000 audit events.
				if d.isMySQL() && f.SortIndex && f.Type == model.FieldTime {
					idx("s_"+f.Name+"_desc", "scope, "+e+" DESC, id")
				}
			}
		}
		if !f.Index || f.Words { // a Words field is matched with LIKE: no index serves it
			continue
		}
		// An Index field is an equality filter on a large kind (model.Field): served by an index, not a scan of
		// the scope. A bool marks a small set (the true ones): a partial index of those where the dialect has them.
		col := d.quote(f.Name)
		if f.Type == model.FieldBool && !d.isMySQL() {
			out = append(out, fmt.Sprintf("CREATE INDEX IF NOT EXISTS %s ON %s (scope, id) WHERE %s = TRUE",
				d.quote("ix_"+tableName(t.kind)+"_f_"+f.Name), t.name, col))
			continue
		}
		idx("f_"+f.Name, col+", scope, id")
	}
	return out
}

func ifNotExists(d *dialect) string {
	if d.name == "mysql" {
		return ""
	}
	return "IF NOT EXISTS "
}
