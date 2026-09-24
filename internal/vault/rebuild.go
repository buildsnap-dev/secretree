package vault

import (
	"fmt"
	"os"
	"path/filepath"

	"filippo.io/age"

	"github.com/buildsnap-dev/secretree/internal/crypt"
	"github.com/buildsnap-dev/secretree/internal/gitx"
)

// Progress receives human-readable progress lines.
type Progress func(format string, args ...any)

// Rebuild reconstructs a bare repository at target generation under
// workDir. It returns the bare repo path and the manifest of the target.
func Rebuild(r *Reader, chain *Chain, target int, identity age.Identity, workDir string, log Progress) (string, *Generation, error) {
	plan, err := chain.RestorePlan(target)
	if err != nil {
		return "", nil, err
	}
	bare := filepath.Join(workDir, "restored.git")
	if err := os.MkdirAll(bare, 0o700); err != nil {
		return "", nil, err
	}
	if _, err := gitx.Run(bare, "init", "--quiet", "--bare"); err != nil {
		return "", nil, err
	}
	for _, g := range plan {
		f := g.Manifest.File(RoleBundle)
		if f == nil {
			log("generation %06d: no bundle (refs/state only)", g.Num)
			continue
		}
		cipher := filepath.Join(workDir, f.Name)
		plain := filepath.Join(workDir, GenName(g.Num)+".bundle")
		if err := r.ExtractFile(filepath.ToSlash(filepath.Join(RepoDir(chain.RepoID), f.Name)), cipher); err != nil {
			return "", nil, err
		}
		if err := crypt.DecryptFile(plain, cipher, identity, crypt.Digest{PlaintextSHA256: f.PlaintextSHA256, CiphertextSHA256: f.CiphertextSHA256}); err != nil {
			return "", nil, fmt.Errorf("generation %06d bundle: %w", g.Num, err)
		}
		_ = os.Remove(cipher)
		for _, p := range g.Manifest.Prerequisites {
			if !gitx.HasObject(bare, p) {
				return "", nil, fmt.Errorf("generation %06d: prerequisite %s missing from rebuilt history", g.Num, p)
			}
		}
		if err := gitx.BundleVerify(bare, plain); err != nil {
			return "", nil, fmt.Errorf("generation %06d: %w", g.Num, err)
		}
		if err := gitx.FetchBundle(bare, plain); err != nil {
			return "", nil, fmt.Errorf("generation %06d: %w", g.Num, err)
		}
		_ = os.Remove(plain)
		log("generation %06d: %s bundle applied (%d bytes)", g.Num, g.Manifest.Kind, f.Size)
	}
	last := plan[len(plan)-1]
	if err := gitx.ApplyRefs(bare, last.Manifest.Refs); err != nil {
		return "", nil, err
	}
	if err := gitx.SetHead(bare, last.Manifest.Source.Head); err != nil {
		return "", nil, err
	}
	if err := gitx.Fsck(bare); err != nil {
		return "", nil, fmt.Errorf("rebuilt repository failed fsck: %w", err)
	}
	got, err := gitx.RefMap(bare)
	if err != nil {
		return "", nil, err
	}
	if d := gitx.DiffRefs(last.Manifest.Refs, got); d != "" {
		return "", nil, fmt.Errorf("rebuilt refs differ from manifest: %s", d)
	}
	return bare, &last, nil
}

// ExtractState decrypts a generation's state archive to a file and returns
// its path and encoding, or "" if the generation has none.
func ExtractState(r *Reader, repoID string, g *Generation, identity age.Identity, workDir string) (string, string, error) {
	f := g.Manifest.File(RoleState)
	if f == nil {
		return "", "", nil
	}
	if err := os.MkdirAll(workDir, 0o700); err != nil {
		return "", "", err
	}
	cipher := filepath.Join(workDir, f.Name)
	plain := filepath.Join(workDir, GenName(g.Num)+".state.tar")
	if err := r.ExtractFile(filepath.ToSlash(filepath.Join(RepoDir(repoID), f.Name)), cipher); err != nil {
		return "", "", err
	}
	if err := crypt.DecryptFile(plain, cipher, identity, crypt.Digest{PlaintextSHA256: f.PlaintextSHA256, CiphertextSHA256: f.CiphertextSHA256}); err != nil {
		return "", "", fmt.Errorf("generation %06d state: %w", g.Num, err)
	}
	_ = os.Remove(cipher)
	return plain, f.ContentEncoding, nil
}
