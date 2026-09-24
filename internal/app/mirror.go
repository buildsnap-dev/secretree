package app

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/buildsnap-dev/secretree/internal/config"
	"github.com/buildsnap-dev/secretree/internal/crypt"
	"github.com/buildsnap-dev/secretree/internal/gitx"
	"github.com/buildsnap-dev/secretree/internal/vault"
)

// mirrorSync brings the plaintext mirror to the vault's latest generation.
// The mirror is derived state: if the chain no longer matches what was
// applied (history rewritten on the host), it is rebuilt from scratch.
func (a *App) mirrorSync(r *repo, vs *vaultState) error {
	ms, err := config.LoadMirrorState(r.Paths)
	if err != nil {
		return err
	}
	if _, err := os.Stat(filepath.Join(r.Paths.Mirror, "HEAD")); err != nil {
		if err := os.MkdirAll(r.Paths.Mirror, 0o700); err != nil {
			return err
		}
		if _, err := gitx.Run(r.Paths.Mirror, "init", "--quiet", "--bare", "--initial-branch=main"); err != nil {
			return err
		}
		ms = &config.MirrorState{}
	}
	chain := vs.Chain
	if ms.AppliedGeneration > 0 {
		g := chain.Get(ms.AppliedGeneration)
		if g == nil || g.ManifestCipherHash != ms.AppliedHash {
			a.debugf("mirror: applied generation %06d no longer matches the vault; rebuilding mirror", ms.AppliedGeneration)
			_ = os.RemoveAll(r.Paths.Mirror)
			if err := os.MkdirAll(r.Paths.Mirror, 0o700); err != nil {
				return err
			}
			if _, err := gitx.Run(r.Paths.Mirror, "init", "--quiet", "--bare", "--initial-branch=main"); err != nil {
				return err
			}
			ms = &config.MirrorState{}
		}
	}
	last := chain.Last()
	if last == nil {
		return nil // empty chain, empty mirror
	}
	if ms.AppliedGeneration == last.Num {
		return nil
	}
	var plan []vault.Generation
	if ms.AppliedGeneration == 0 {
		if plan, err = chain.RestorePlan(last.Num); err != nil {
			return err
		}
	} else {
		for _, g := range chain.Gens {
			if g.Num > ms.AppliedGeneration {
				if g.Opaque() {
					return fmt.Errorf("generation %06d is not readable by this key", g.Num)
				}
				plan = append(plan, g)
			}
		}
	}
	tmp, cleanup, err := r.tmpDir("mirror")
	if err != nil {
		return err
	}
	defer cleanup()
	for _, g := range plan {
		f := g.Manifest.File(vault.RoleBundle)
		if f == nil {
			continue
		}
		cipher := filepath.Join(tmp, f.Name)
		plain := filepath.Join(tmp, vault.GenName(g.Num)+".bundle")
		if err := vs.Reader.ExtractFile(vault.RepoDir(r.Cfg.RepoID)+"/"+f.Name, cipher); err != nil {
			return err
		}
		if err := crypt.DecryptFile(plain, cipher, r.identity, crypt.Digest{PlaintextSHA256: f.PlaintextSHA256, CiphertextSHA256: f.CiphertextSHA256}); err != nil {
			return fmt.Errorf("generation %06d bundle: %w", g.Num, err)
		}
		_ = os.Remove(cipher)
		if err := gitx.BundleVerify(r.Paths.Mirror, plain); err != nil {
			return fmt.Errorf("generation %06d: %w", g.Num, err)
		}
		if err := gitx.FetchBundle(r.Paths.Mirror, plain); err != nil {
			return fmt.Errorf("generation %06d: %w", g.Num, err)
		}
		_ = os.Remove(plain)
		a.debugf("mirror: generation %06d applied", g.Num)
	}
	if err := gitx.ApplyRefs(r.Paths.Mirror, last.Manifest.Refs); err != nil {
		return err
	}
	if err := setMirrorHead(r.Paths.Mirror, last.Manifest.Source.Head, last.Manifest.Refs); err != nil {
		return err
	}
	ms.AppliedGeneration = last.Num
	ms.AppliedHash = last.ManifestCipherHash
	return config.SaveMirrorState(r.Paths, ms)
}

// setMirrorHead points HEAD at want when that ref exists, else at a
// sensible default branch, so clones always get a checkout.
func setMirrorHead(mirror, want string, refs map[string]string) error {
	if strings.HasPrefix(want, "refs/heads/") {
		if _, ok := refs[want]; ok {
			return gitx.SetHead(mirror, want)
		}
	} else if want != "" {
		if _, err := gitx.Run(mirror, "cat-file", "-e", want); err == nil {
			return gitx.SetHead(mirror, want)
		}
	}
	for _, cand := range []string{"refs/heads/main", "refs/heads/master"} {
		if _, ok := refs[cand]; ok {
			return gitx.SetHead(mirror, cand)
		}
	}
	for _, ref := range gitx.SortedRefs(refs) {
		name := strings.Fields(ref)[0]
		if strings.HasPrefix(name, "refs/heads/") {
			return gitx.SetHead(mirror, name)
		}
	}
	return gitx.SetHead(mirror, "refs/heads/main")
}

// mirrorRefs lists what the helper advertises: heads, tags, and any
// secretree namespaces; never remotes or the backup-only extras.
func mirrorRefs(mirror string) (map[string]string, error) {
	all, err := gitx.RefMap(mirror)
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for k, v := range all {
		if strings.HasPrefix(k, "refs/heads/") || strings.HasPrefix(k, "refs/tags/") || strings.HasPrefix(k, "refs/secretree/") || strings.HasPrefix(k, "refs/notes/") {
			out[k] = v
		}
	}
	return out, nil
}
