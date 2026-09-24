package app

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/buildsnap-dev/secretree/internal/config"
	"github.com/buildsnap-dev/secretree/internal/crypt"
	"github.com/buildsnap-dev/secretree/internal/gitx"
	"github.com/buildsnap-dev/secretree/internal/vault"
)

// prove fetches the vault afresh from the remote, verifies the whole chain,
// rebuilds generation n and compares it with the refs captured at backup
// time. wantManifestHash pins the remote copy to what we just pushed.
func (a *App) prove(r *repo, n int, wantRefs map[string]string, wantManifestHash string) (string, error) {
	tmp, cleanup, err := r.tmpDir("proof")
	if err != nil {
		return "", err
	}
	defer cleanup()
	dir := filepath.Join(tmp, "vault")
	if err := cloneVault(r.Cfg.VaultURL, dir); err != nil {
		return "", err
	}
	reader := &vault.Reader{Dir: dir}
	pub, _ := r.Keys.PublicKey()
	meta, signers, err := vault.LoadMeta(reader, pub)
	if err != nil {
		return "", err
	}
	chain, err := vault.LoadChain(reader, meta.VaultID, r.Cfg.RepoID, r.identity, signers)
	if err != nil {
		return "", err
	}
	g := chain.Get(n)
	if g == nil {
		return "", fmt.Errorf("generation %06d is not on the remote", n)
	}
	if wantManifestHash != "" && g.ManifestCipherHash != wantManifestHash {
		return "", fmt.Errorf("remote manifest %06d differs from what was pushed", n)
	}
	bare, _, err := vault.Rebuild(reader, chain, n, r.identity, filepath.Join(tmp, "rebuild"), a.debugf)
	if err != nil {
		return "", err
	}
	got, err := gitx.RefMap(bare)
	if err != nil {
		return "", err
	}
	if d := gitx.DiffRefs(wantRefs, got); d != "" {
		return "", fmt.Errorf("rebuilt refs differ from source: %s", d)
	}
	if g.Manifest.File(vault.RoleState) != nil {
		if _, _, err := vault.ExtractState(reader, r.Cfg.RepoID, g, r.identity, filepath.Join(tmp, "state")); err != nil {
			return "", err
		}
	}
	plan, _ := chain.RestorePlan(n)
	return fmt.Sprintf("%d generations verified, %d applied, %d refs match", len(chain.Gens), len(plan), len(got)), nil
}

// VerifyOptions configures Verify.
type VerifyOptions struct {
	Dir        string
	Generation int  // 0 = latest
	Quick      bool // signatures, hashes and chain only; no rebuild
	All        bool // also check every ciphertext of every generation against its manifest
}

// Verify re-checks the vault from a fresh fetch and rebuilds a generation.
func (a *App) Verify(o VerifyOptions) error {
	r, err := a.openRepo(o.Dir)
	if err != nil {
		return err
	}
	unlock, err := r.lock()
	if err != nil {
		return err
	}
	defer unlock()
	tmp, cleanup, err := r.tmpDir("verify")
	if err != nil {
		return err
	}
	defer cleanup()
	dir := filepath.Join(tmp, "vault")
	if err := cloneVault(r.Cfg.VaultURL, dir); err != nil {
		return err
	}
	reader := &vault.Reader{Dir: dir}
	pub, _ := r.Keys.PublicKey()
	meta, signers, err := vault.LoadMeta(reader, pub)
	if err != nil {
		return err
	}
	a.logf("vault.json: signed, %d recipient(s), %d signer(s)", len(meta.Recipients), len(signers.Active))
	chain, err := vault.LoadChain(reader, meta.VaultID, r.Cfg.RepoID, r.identity, signers)
	if err != nil {
		return err
	}
	if chain.Last() == nil {
		return errors.New("no generations for this repo yet")
	}
	for _, g := range chain.Gens {
		if g.Opaque() {
			a.logf("generation %06d: opaque (predates this key)  signed, chained", g.Num)
			continue
		}
		var size int64
		for _, f := range g.Manifest.Files {
			size += f.Size
		}
		a.logf("generation %06d: %-11s %s  %3d refs  %9s  signed, chained", g.Num, g.Manifest.Kind,
			g.Manifest.Created.Format("2006-01-02 15:04"), len(g.Manifest.Refs), humanBytes(size))
	}
	if o.All {
		checked := 0
		for _, g := range chain.Gens {
			if g.Opaque() {
				continue
			}
			for _, f := range g.Manifest.Files {
				p := filepath.Join(tmp, f.Name)
				if err := reader.ExtractFile(vault.RepoDir(r.Cfg.RepoID)+"/"+f.Name, p); err != nil {
					return err
				}
				h, err := crypt.SHA256File(p)
				_ = os.Remove(p)
				if err != nil {
					return err
				}
				if h != f.CiphertextSHA256 {
					return fmt.Errorf("generation %06d: %s is CORRUPT on the remote (sha256 %s, manifest says %s)", g.Num, f.Name, h[:12], f.CiphertextSHA256[:12])
				}
				checked++
			}
		}
		a.logf("every ciphertext matches its manifest (%d files, %s)", checked, humanBytes(chain.Bytes()))
	}
	if o.Quick {
		a.logf("chain OK (%d generations, %s); rebuild skipped (--quick)", len(chain.Gens), humanBytes(chain.Bytes()))
		return nil
	}
	target := o.Generation
	if target == 0 {
		target = chain.Last().Num
	}
	bare, g, err := vault.Rebuild(reader, chain, target, r.identity, filepath.Join(tmp, "rebuild"), a.debugf)
	if err != nil {
		return fmt.Errorf("rebuild of generation %06d FAILED: %w", target, err)
	}
	if g.Manifest.File(vault.RoleState) != nil {
		if _, _, err := vault.ExtractState(reader, r.Cfg.RepoID, g, r.identity, filepath.Join(tmp, "state")); err != nil {
			return err
		}
	}
	got, _ := gitx.RefMap(bare)
	a.logf("generation %06d rebuilt from the remote: %d refs, fsck clean", target, len(got))
	if cur, err := gitx.RefMap(r.Work); err == nil {
		if d := gitx.DiffRefs(got, cur); d != "" {
			a.logf("note: source has changed since generation %06d: %s", target, d)
		} else {
			a.logf("source refs match generation %06d exactly", target)
		}
	}
	status, err := config.LoadStatus(r.Paths)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	status.LastProof = &now
	status.LastProofGeneration = target
	status.Generations = len(chain.Gens)
	status.ChainBytes = chain.Bytes()
	return config.SaveStatus(r.Paths, status)
}
