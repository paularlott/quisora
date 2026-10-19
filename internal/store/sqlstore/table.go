package sqlstore

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/paularlott/gossip/hlc"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"
)

const (
	uniqueTable = "qsr_unique"
	feedTable   = "qsr_feed"
	schemaTable = "qsr_schema"
)

// table holds the generated SQL for one kind. Statements use ? placeholders already rewritten for the dialect.
type table struct {
	kind   model.Kind
	name   string // quoted table name
	fields []model.Field
	cols   string // every column, in scan order

	get    string // WHERE id = ? and live
	lookup string // WHERE id = ?, whatever the state
	meta   string // version, origin, deleted, expires, uniq, epoch, created_v of one id, row-locked
	insert string
	update string

	uInsert, uHolder, uSteal string // unique-table statements for this kind
}

func newTable(d *dialect, kind model.Kind) *table {
	s := model.Schemas[kind]
	t := &table{kind: kind, name: d.quote("qsr_" + string(kind)), fields: s.Fields}
	cols := []string{"id", "version", "origin", "deleted", "scope", "expires", "seq", "uniq", "data", "epoch", "created_v"}
	for _, f := range s.Fields {
		cols = append(cols, f.Name)
	}
	q := make([]string, len(cols))
	for i, c := range cols {
		q[i] = d.quote(c)
	}
	t.cols = strings.Join(q, ", ")
	marks := strings.TrimSuffix(strings.Repeat("?, ", len(cols)), ", ")
	t.get = d.bind("SELECT " + t.cols + " FROM " + t.name + " WHERE id = ? AND deleted = FALSE AND (expires IS NULL OR expires > ?)")
	t.meta = d.bind("SELECT version, origin, deleted, expires, uniq, epoch, created_v FROM " + t.name + " WHERE id = ?" + d.lockClause(""))
	t.lookup = d.bind("SELECT " + t.cols + " FROM " + t.name + " WHERE id = ?")
	t.insert = d.bind("INSERT INTO " + t.name + " (" + t.cols + ") VALUES (" + marks + ")")
	sets := make([]string, 0, len(cols)-1)
	for _, c := range q[1:] {
		sets = append(sets, c+" = ?")
	}
	t.update = d.bind("UPDATE " + t.name + " SET " + strings.Join(sets, ", ") + " WHERE id = ?")
	t.uInsert = d.bind(d.insertIgnore(uniqueTable, "kind, value, id", "?, ?, ?"))
	t.uHolder = d.bind("SELECT u.id, k.version, k.origin, k.deleted, k.expires, k.created_v FROM " + uniqueTable + " u LEFT JOIN " + t.name +
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

func decodeUnique(s sql.NullString) []string {
	if !s.Valid || s.String == "" {
		return nil
	}
	var u []string
	_ = json.Unmarshal([]byte(s.String), &u)
	return u
}

func blobArg(b []byte) any {
	if b == nil {
		return nil
	}
	return b
}

// args returns the column values of rec in insert order. Tombstones carry no scope, data, fields or expiry.
func (t *table) args(rec *store.Record, seq int64) ([]any, error) {
	a := make([]any, 0, 10+len(t.fields))
	var expires any
	scope := rec.Scope
	if rec.Deleted {
		scope = ""
	} else if !rec.Expires.IsZero() {
		expires = rec.Expires.UnixMicro()
	}
	var uniq any
	var data []byte
	var epoch, created int64
	if !rec.Deleted {
		uniq, data, epoch, created = encodeUnique(rec.Unique), rec.Data, int64(rec.Epoch), int64(rec.Created)
	}
	a = append(a, rec.ID, int64(rec.Version), rec.Origin, rec.Deleted, scope, expires, seq, uniq, blobArg(data), epoch, created)
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
	return a, nil
}

type scanner interface{ Scan(dest ...any) error }

// scan reads a row selected with t.cols.
func (t *table) scan(r scanner) (*store.Record, int64, error) {
	var (
		id, origin, scope string
		version, seq      int64
		epoch, created    int64
		deleted           bool
		expires           sql.NullInt64
		uniq              sql.NullString
		data              []byte
	)
	dest := []any{&id, &version, &origin, &deleted, &scope, &expires, &seq, &uniq, &data, &epoch, &created}
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
		return nil, 0, err
	}
	rec := &store.Record{Kind: t.kind, ID: id, Version: hlc.Timestamp(version), Origin: origin, Deleted: deleted,
		Scope: scope, Unique: decodeUnique(uniq), Data: data, Epoch: hlc.Timestamp(epoch), Created: hlc.Timestamp(created)}
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
	return rec, seq, nil
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
		"seq BIGINT NOT NULL DEFAULT 0",
		"uniq " + d.textType() + " NULL",
		"data " + d.blobType() + " NULL",
		"epoch BIGINT NOT NULL DEFAULT 0",     // store.Record.Epoch
		"created_v BIGINT NOT NULL DEFAULT 0", // store.Record.Created
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
		out = append(out, fmt.Sprintf("CREATE INDEX %s%s ON %s (%s)", ifNotExists(d), d.quote("ix_"+string(t.kind)+"_"+name), t.name, keys))
	}
	idx("scope", "scope, id")
	idx("seq", "seq")
	idx("expires", "expires")
	if d.isMySQL() {
		idx("tomb", "deleted, version")
	} else { // partial: the planner must never pick it for the (far more common) deleted = FALSE queries
		out = append(out, fmt.Sprintf("CREATE INDEX IF NOT EXISTS %s ON %s (version) WHERE deleted = TRUE",
			d.quote("ix_"+string(t.kind)+"_tomb"), t.name))
	}
	for _, f := range t.fields {
		if !f.Sort {
			continue
		}
		if e := d.sortIndexExpr(f); e != "" {
			idx("s_"+f.Name, "scope, "+e+", id")
		}
	}
	return out
}

func ifNotExists(d *dialect) string {
	if d.name == "mysql" {
		return ""
	}
	return "IF NOT EXISTS "
}
