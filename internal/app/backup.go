package app

import (
	"fmt"
	"time"

	"github.com/buildsnap-dev/secretree/internal/config"
)

// BackupOptions configures Backup.
type BackupOptions struct {
	Dir     string
	Full    bool
	NoProof bool // skip the restore proof (tests of failure paths only)
}

// Backup snapshots the whole local repository (every ref, plus the state
// archive) as one generation and proves it restorable.
func (a *App) Backup(o BackupOptions) (err error) {
	r, err := a.openRepo(o.Dir)
	if err != nil {
		return err
	}
	unlock, err := r.lock()
	if err != nil {
		return err
	}
	defer unlock()
	status, err := config.LoadStatus(r.Paths)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			now := time.Now().UTC()
			status.LastError = err.Error()
			status.LastErrorTime = &now
			_ = config.SaveStatus(r.Paths, status)
		}
	}()
	vs, err := a.loadVault(r)
	if err != nil {
		return err
	}
	res, err := a.writeGeneration(r, vs, status, genOptions{Source: r.Work, Full: o.Full, WithState: true})
	if err != nil {
		return err
	}
	if res.Skipped {
		a.logf("nothing to back up (generation %06d is current)", res.Number)
		return nil
	}
	a.logf("generation %06d pushed: %s, %d refs, %s", res.Number, res.Kind, len(res.Refs), humanBytes(res.Bytes))
	if o.NoProof {
		return nil
	}
	summary, err := a.prove(r, res.Number, res.Refs, res.ManifestHash)
	if err != nil {
		return fmt.Errorf("RESTORE PROOF FAILED for generation %06d: %w", res.Number, err)
	}
	now := time.Now().UTC()
	status.LastProof = &now
	status.LastProofGeneration = res.Number
	if err := config.SaveStatus(r.Paths, status); err != nil {
		return err
	}
	a.logf("restore proof OK: generation %06d rebuilt from the remote (%s)", res.Number, summary)
	return nil
}
