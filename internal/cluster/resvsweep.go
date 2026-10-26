package cluster

import (
	"context"
	"errors"
	"time"

	"github.com/paularlott/gossip/partition"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"
)

// ReservationSweep is the position of SweepReservations in the reservations (it resumes where the last call stopped).
type ReservationSweep struct{ after string }

// holdsReservation reports whether the record h, the holder a reservation names, still lists the value that reservation
// stands for (the value itself is not known: a long one is stored hashed).
func holdsReservation(h *store.Record, resv string) bool {
	for _, g := range globalsOf(h) {
		if reservationID(h.Kind, g) == resv {
			return true
		}
	}
	return false
}

// SweepReservations looks at the next batch of reservations this node holds and releases those whose holder is gone: a
// claim whose record was never written (the claimant died between the two writes), or a record deleted or changed
// whose release was lost. The claim of a value takes a reservation over only on positive evidence (prepareClaim), and a
// holder its owner does not have is none, so these are found here: for each reservation older than reservationGrace
// whose holder is not known here to hold it, the holder is read through the owner of its partition (a linearizable
// read: a lagging copy cannot condemn it), and if it does not exist, or is deleted, or does not list the value, the
// reservation is released with a compare-and-swap on the version read. The housekeeping leader runs it, a batch per
// round; it reports how many it released. Without gossip there are no reservations.
func (n *Node) SweepReservations(ctx context.Context, sw *ReservationSweep, batch int) (released int, err error) {
	if n.gc == nil {
		return 0, nil
	}
	res, err := n.st.inner.List(ctx, model.KindReservation, store.ListQuery{After: sw.after, Limit: batch})
	if err != nil {
		return 0, err
	}
	// The position moves on only once the whole batch is judged: an error part-way leaves it, and the next call reads
	// the batch again instead of skipping what was not reached.
	next := "" // the end: the next call starts again
	if len(res.Records) >= batch {
		next = res.Records[len(res.Records)-1].ID
	}
	now := time.Now()
	type suspect struct {
		rec *store.Record
		r   model.Reservation
	}
	byKind := map[model.Kind][]suspect{}
	for _, rec := range res.Records {
		var r model.Reservation
		if store.Decode(rec, &r) != nil || now.Sub(r.Updated) < reservationGrace {
			continue
		}
		if h, err := n.st.lookup(ctx, r.HolderKind, r.HolderID); err != nil {
			return released, err
		} else if h != nil && h.Live(now) && holdsReservation(h, rec.ID) {
			continue // as far as this node can see it is held: nothing to ask
		}
		byKind[r.HolderKind] = append(byKind[r.HolderKind], suspect{rec, r})
	}
	for kind, ss := range byKind {
		ids := make([]string, len(ss))
		for i, s := range ss {
			ids[i] = s.r.HolderID
		}
		fresh, err := n.st.Fresh(ctx, kind, ids)
		if err != nil {
			return released, err
		}
		for _, s := range ss {
			if h := fresh[s.r.HolderID]; h != nil && h.Live(now) && holdsReservation(h, s.rec.ID) {
				continue
			}
			_, err := n.st.submit(ctx, partitionNum(s.rec.ID), &change{Op: opRelease, Kind: string(kind), ID: s.r.HolderID,
				Resv: s.rec.ID, Expect: uint64(s.rec.Version)})
			var re *partition.RefusedError
			switch {
			case err == nil:
				released++
				n.log.Info("a reserved value whose holder is gone was released", "reservation", s.rec.ID, "holder_kind",
					string(kind), "holder", s.r.HolderID)
			case errors.As(err, &re) && (re.Code == whyStale || re.Code == whyNotHeld):
				// taken over or released meanwhile
			default:
				return released, err
			}
		}
	}
	sw.after = next
	return released, nil
}
