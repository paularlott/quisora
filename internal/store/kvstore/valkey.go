package kvstore

import (
	"context"
	"crypto/sha1"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"strconv"

	"github.com/paularlott/quisora/internal/model"
	"github.com/valkey-io/valkey-go"
)

// ValkeyConfig configures the Valkey engine. The server must be a single primary (standalone or behind Sentinel
// failover); the commit script touches many keys so Valkey Cluster is not supported.
type ValkeyConfig struct {
	Addrs     []string
	Username  string
	Password  string
	DB        int
	KeyPrefix string // prepended to every key so several stores can share a server
	TLS       bool
	// TLSConfig verifies Valkey (a private CA, the name to verify) and presents a client certificate; nil with TLS:
	// the system's roots and the address's host.
	TLSConfig *tls.Config
	// PipelineMultiplex is the exponent of the number of pipelined connections per node (2^n); 0 uses valkey-go's default.
	PipelineMultiplex int
}

// commitScript validates the keys a transaction read (by SHA-1 of their value, "" = absent) and applies its
// operations atomically. ARGV: prefix, ncheck, (key, digest)*, nops, ops... where each op is
//
//	S key value | D key | A bucket member exp | R bucket member | F recKey body entry oldSeq
//
// It returns -1 on a validation failure (the caller retries) and otherwise the last sequence number assigned.
// F bumps meta/seq, stamps the sequence into the first 8 bytes of body, stores the record and feed entry and
// removes the previous feed entry; an empty body deletes the record and its feed entry instead.
const commitScript = `
local p = ARGV[1]
local i = 2
local nc = tonumber(ARGV[i]); i = i + 1
for c = 1, nc do
  local v = redis.call('GET', p .. ARGV[i])
  local d = ''
  if v then d = redis.sha1hex(v) end
  if d ~= ARGV[i + 1] then return -1 end
  i = i + 2
end
local no = tonumber(ARGV[i]); i = i + 1
local last = 0
for o = 1, no do
  local c = ARGV[i]; i = i + 1
  if c == 'S' then
    redis.call('SET', p .. ARGV[i], ARGV[i + 1]); i = i + 2
  elseif c == 'D' then
    redis.call('DEL', p .. ARGV[i]); i = i + 1
  elseif c == 'A' then
    redis.call('ZADD', p .. 'z/' .. ARGV[i], 0, ARGV[i + 1])
    local e = tonumber(ARGV[i + 2])
    if e > 0 then
      redis.call('ZADD', p .. 'x/' .. ARGV[i], e, ARGV[i + 1])
    else
      redis.call('ZREM', p .. 'x/' .. ARGV[i], ARGV[i + 1])
    end
    i = i + 3
  elseif c == 'R' then
    redis.call('ZREM', p .. 'z/' .. ARGV[i], ARGV[i + 1])
    redis.call('ZREM', p .. 'x/' .. ARGV[i], ARGV[i + 1])
    i = i + 2
  elseif c == 'F' then
    local rk, body, entry, old = ARGV[i], ARGV[i + 1], ARGV[i + 2], tonumber(ARGV[i + 3])
    i = i + 4
    if old > 0 then
      redis.call('ZREM', p .. 'z/seq', string.format('%020.0f', old) .. '/' .. entry)
    end
    if body == '' then
      redis.call('DEL', p .. rk)
    else
      local seq = redis.call('INCR', p .. 'meta/seq')
      local h = ''
      for b = 7, 0, -1 do
        h = h .. string.char(math.floor(seq / (256 ^ b)) % 256)
      end
      redis.call('SET', p .. rk, h .. string.sub(body, 9))
      redis.call('ZADD', p .. 'z/seq', 0, string.format('%020.0f', seq) .. '/' .. entry)
      last = seq
    end
  end
end
return last
`

var commitLua = valkey.NewLuaScript(commitScript)

type valkeyEngine struct {
	c      valkey.Client
	prefix string
}

// OpenValkey connects to Valkey and returns a store using it.
func OpenValkey(ctx context.Context, cfg ValkeyConfig) (*Store, error) {
	if len(cfg.Addrs) == 0 {
		return nil, fmt.Errorf("kvstore: valkey needs at least one address")
	}
	opt := valkey.ClientOption{
		InitAddress:       cfg.Addrs,
		Username:          cfg.Username,
		Password:          cfg.Password,
		SelectDB:          cfg.DB,
		DisableCache:      true,
		ForceSingleClient: true,
	}
	if cfg.PipelineMultiplex != 0 {
		opt.PipelineMultiplex = cfg.PipelineMultiplex
	}
	if cfg.TLS {
		opt.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
		if cfg.TLSConfig != nil {
			opt.TLSConfig = cfg.TLSConfig.Clone()
			opt.TLSConfig.MinVersion = max(opt.TLSConfig.MinVersion, tls.VersionTLS12)
		}
	}
	c, err := valkey.NewClient(opt)
	if err != nil {
		return nil, fmt.Errorf("kvstore: connect valkey: %w", err)
	}
	e := &valkeyEngine{c: c, prefix: cfg.KeyPrefix}
	// Create the feed id once (shared by every process using this prefix), then read it back.
	if err := c.Do(ctx, c.B().Set().Key(e.k(metaFeed)).Value(model.NewID()).Nx().Build()).Error(); err != nil && !valkey.IsValkeyNil(err) {
		c.Close()
		return nil, fmt.Errorf("kvstore: init valkey: %w", err)
	}
	feedID, err := c.Do(ctx, c.B().Get().Key(e.k(metaFeed)).Build()).ToString()
	if err != nil {
		c.Close()
		return nil, fmt.Errorf("kvstore: init valkey: %w", err)
	}
	st := newStore(ctx, e, feedID)
	if err := st.checkFormat(ctx); err != nil {
		e.Close()
		return nil, err
	}
	return st, nil
}

func (e *valkeyEngine) k(key string) string { return e.prefix + key }

func (e *valkeyEngine) Close() error {
	e.c.Close()
	return nil
}

// deletePrefix removes every key of this store (tests).
func (e *valkeyEngine) deletePrefix(ctx context.Context) error {
	var cursor uint64
	for {
		se, err := e.c.Do(ctx, e.c.B().Scan().Cursor(cursor).Match(e.prefix+"*").Count(1000).Build()).AsScanEntry()
		if err != nil {
			return err
		}
		if len(se.Elements) > 0 {
			if err := e.c.Do(ctx, e.c.B().Unlink().Key(se.Elements...).Build()).Error(); err != nil {
				return err
			}
		}
		cursor = se.Cursor
		if cursor == 0 {
			return nil
		}
	}
}

func (e *valkeyEngine) Get(ctx context.Context, key string) ([]byte, error) {
	b, err := e.c.Do(ctx, e.c.B().Get().Key(e.k(key)).Build()).AsBytes()
	if valkey.IsValkeyNil(err) {
		return nil, nil
	}
	return b, err
}

func (e *valkeyEngine) MGet(ctx context.Context, keys []string) ([][]byte, error) {
	out := make([][]byte, len(keys))
	const chunk = 1000
	for from := 0; from < len(keys); from += chunk {
		to := min(from+chunk, len(keys))
		ks := make([]string, to-from)
		for i, k := range keys[from:to] {
			ks[i] = e.k(k)
		}
		arr, err := e.c.Do(ctx, e.c.B().Mget().Key(ks...).Build()).ToArray()
		if err != nil {
			return nil, err
		}
		for i := range arr {
			if arr[i].IsNil() {
				continue
			}
			b, err := arr[i].AsBytes()
			if err != nil {
				return nil, err
			}
			out[from+i] = b
		}
	}
	return out, nil
}

func (e *valkeyEngine) zkey(bucket string) string { return e.k("z/" + bucket) }
func (e *valkeyEngine) xkey(bucket string) string { return e.k("x/" + bucket) }

// card returns the member count and the number of expired members at nowMs.
func (e *valkeyEngine) card(ctx context.Context, bucket string, nowMs int64) (int, int, error) {
	res := e.c.DoMulti(ctx,
		e.c.B().Zcard().Key(e.zkey(bucket)).Build(),
		e.c.B().Zcount().Key(e.xkey(bucket)).Min("-inf").Max(strconv.FormatInt(nowMs, 10)).Build())
	n, err := res[0].AsInt64()
	if err != nil {
		return 0, 0, err
	}
	x, err := res[1].AsInt64()
	if err != nil {
		return 0, 0, err
	}
	return int(n), int(x), nil
}

func (e *valkeyEngine) Count(ctx context.Context, bucket string, nowMs int64) (int, error) {
	n, x, err := e.card(ctx, bucket, nowMs)
	return n - x, err
}

func (e *valkeyEngine) Page(ctx context.Context, bucket string, reverse bool, offset, limit int, nowMs int64) ([]string, int, error) {
	n, x, err := e.card(ctx, bucket, nowMs)
	if err != nil {
		return nil, 0, err
	}
	total := n - x
	if total == 0 || offset >= total {
		return []string{}, total, nil
	}
	lo, hi := "-", "+"
	cmd := "ZRANGEBYLEX"
	if reverse {
		lo, hi, cmd = "+", "-", "ZREVRANGEBYLEX"
	}
	args := []string{lo, hi}
	skip := offset
	count := limit
	var expired map[string]struct{}
	if x > 0 {
		// Expired members still sit in the index (until purged): widen the window and filter them out.
		exp, err := e.c.Do(ctx, e.c.B().Zrangebyscore().Key(e.xkey(bucket)).Min("-inf").Max(strconv.FormatInt(nowMs, 10)).Build()).AsStrSlice()
		if err != nil {
			return nil, 0, err
		}
		expired = make(map[string]struct{}, len(exp))
		for _, m := range exp {
			expired[m] = struct{}{}
		}
		skip = 0
		if limit > 0 {
			count = offset + limit + x
		}
	}
	if skip > 0 || count > 0 {
		if count <= 0 {
			count = n
		}
		args = append(args, "LIMIT", strconv.Itoa(skip), strconv.Itoa(count))
	}
	members, err := e.c.Do(ctx, e.c.B().Arbitrary(cmd).Keys(e.zkey(bucket)).Args(args...).Build()).AsStrSlice()
	if err != nil {
		return nil, 0, err
	}
	if x > 0 {
		live := members[:0]
		for _, m := range members {
			if _, gone := expired[m]; !gone {
				live = append(live, m)
			}
		}
		members = live
		if offset >= len(members) {
			members = nil
		} else {
			members = members[offset:]
		}
		if limit > 0 && len(members) > limit {
			members = members[:limit]
		}
	}
	if members == nil {
		members = []string{}
	}
	return members, total, nil
}

func (e *valkeyEngine) Range(ctx context.Context, bucket, from, to string, limit int) ([]string, error) {
	lo, hi := "-", "+"
	if from != "" {
		lo = "[" + from
	}
	if to != "" {
		hi = "[" + to
	}
	args := []string{lo, hi}
	if limit > 0 {
		args = append(args, "LIMIT", "0", strconv.Itoa(limit))
	}
	out, err := e.c.Do(ctx, e.c.B().Arbitrary("ZRANGEBYLEX").Keys(e.zkey(bucket)).Args(args...).Build()).AsStrSlice()
	if out == nil {
		out = []string{}
	}
	return out, err
}

func (e *valkeyEngine) Update(ctx context.Context, fn func(tx txn) error) error {
	return retry(ctx, func() error {
		vt := &valkeyTxn{e: e, ctx: ctx, reads: map[string]string{}, over: map[string]overlay{}}
		if err := fn(vt); err != nil {
			return err
		}
		return vt.commit()
	})
}

type overlay struct {
	val  []byte
	gone bool
}

type valkeyTxn struct {
	e     *valkeyEngine
	ctx   context.Context
	reads map[string]string // key -> sha1 hex of the value first read ("" = absent)
	over  map[string]overlay
	ops   []string
	nops  int
}

func (v *valkeyTxn) Get(key string) ([]byte, error) {
	if o, ok := v.over[key]; ok {
		if o.gone {
			return nil, nil
		}
		return o.val, nil
	}
	b, err := v.e.Get(v.ctx, key)
	if err != nil {
		return nil, err
	}
	if _, seen := v.reads[key]; !seen {
		d := ""
		if b != nil {
			sum := sha1.Sum(b)
			d = hex.EncodeToString(sum[:])
		}
		v.reads[key] = d
	}
	return b, nil
}

func (v *valkeyTxn) op(args ...string) {
	v.ops = append(v.ops, args...)
	v.nops++
}

func (v *valkeyTxn) Set(key string, val []byte) {
	v.over[key] = overlay{val: val}
	v.op("S", key, string(val))
}

func (v *valkeyTxn) Delete(key string) {
	v.over[key] = overlay{gone: true}
	v.op("D", key)
}

func (v *valkeyTxn) SetAdd(bucket, member string, expMs int64) {
	v.op("A", bucket, member, strconv.FormatInt(expMs, 10))
}

func (v *valkeyTxn) SetDel(bucket, member string) { v.op("R", bucket, member) }

func (v *valkeyTxn) Feed(recKey string, body []byte, entry string, oldSeq uint64) {
	v.op("F", recKey, string(body), entry, strconv.FormatUint(oldSeq, 10))
}

func (v *valkeyTxn) commit() error {
	if v.nops == 0 {
		return nil
	}
	args := make([]string, 0, 4+2*len(v.reads)+len(v.ops))
	args = append(args, v.e.prefix, strconv.Itoa(len(v.reads)))
	for k, d := range v.reads {
		args = append(args, k, d)
	}
	args = append(args, strconv.Itoa(v.nops))
	args = append(args, v.ops...)
	n, err := commitLua.Exec(v.ctx, v.e.c, nil, args).AsInt64()
	if err != nil {
		return fmt.Errorf("kvstore: valkey commit: %w", err)
	}
	if n < 0 {
		return errConflict
	}
	return nil
}

func (e *valkeyEngine) wipe(ctx context.Context, newFeedID string) error {
	if err := e.deletePrefix(ctx); err != nil {
		return fmt.Errorf("kvstore: wipe valkey: %w", err)
	}
	return e.c.Do(ctx, e.c.B().Set().Key(e.k(metaFeed)).Value(newFeedID).Build()).Error()
}
