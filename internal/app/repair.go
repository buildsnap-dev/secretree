package app

import (
	"errors"
	"fmt"

	"github.com/buildsnap-dev/secretree/internal/config"
	"github.com/buildsnap-dev/secretree/internal/gitx"
	"github.com/buildsnap-dev/secretree/internal/vault"
)

// Repair rebuilds a vault whose host lost or rewrote generations. It
// accepts whatever chain the host still has (after verifying it), then
// writes a new full generation from this device's data (the mirror for
// helper-synced repositories, the work tree otherwise), which carries
// every ref including the collaboration history, and proves the result
// restorable. Other members' next sync sees a longer, verified chain.
func (a *App) Repair(dir string) error {
	r, err := a.openRepo(dir)
	if err != nil {
		return err
	}
	unlock, err := r.lock()
	if err != nil {
		return err
	}
	defer unlock()
	st, err := config.LoadStatus(r.Paths)
	if err != nil {
		return err
	}
	// first, show what happened
	r.acceptRollback = false
	if _, err := a.loadVault(r); err == nil {
		a.logf("the vault matches what this device recorded; nothing to repair")
		return nil
	} else if !errors.Is(err, ErrRolledBack) {
		return err
	} else {
		a.logf("%v", err)
	}
	r.acceptRollback = true
	vs, err := a.loadVault(r)
	if err != nil {
		return fmt.Errorf("the remaining chain does not verify either: %w", err)
	}
	last := 0
	if vs.Chain.Last() != nil {
		last = vs.Chain.Last().Num
	}
	a.logf("host chain verified up to generation %06d; this device knew %06d", last, st.LastGeneration)

	src, withState := r.Work, true
	if ms, err := config.LoadMirrorState(r.Paths); err == nil && ms.AppliedGeneration > 0 {
		// the mirror holds every ref this device ever synced, collab included
		src, withState = r.Paths.Mirror, false
		a.logf("rebuilding from the local mirror (%d refs)", countRefs(src))
	} else {
		a.logf("rebuilding from the work tree")
	}
	res, err := a.writeGeneration(r, vs, st, genOptions{Source: src, Full: true, WithState: withState})
	if err != nil {
		return err
	}
	if src == r.Paths.Mirror {
		_ = config.SaveMirrorState(r.Paths, &config.MirrorState{AppliedGeneration: res.Number, AppliedHash: res.ManifestHash})
	}
	a.logf("generation %06d written (full, %d refs, %s)", res.Number, len(res.Refs), humanBytes(res.Bytes))
	summary, err := a.prove(r, res.Number, res.Refs, res.ManifestHash)
	if err != nil {
		return fmt.Errorf("RESTORE PROOF FAILED after repair: %w", err)
	}
	a.logf("restore proof OK (%s)", summary)
	a.logf("done. Other members should run `secretree verify`; their next fetch adopts the repaired chain. Consider protecting the vault branch on the host and rotating its credentials.")
	_ = vault.GenName
	return nil
}

func countRefs(dir string) int {
	m, _ := gitx.RefMap(dir)
	return len(m)
}
