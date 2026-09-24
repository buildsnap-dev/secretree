package app

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/buildsnap-dev/secretree/internal/gitx"
)

// errPushRejected means another writer appended to the vault first.
var errPushRejected = errors.New("vault rejected the push: another writer appended a generation first")

// ensureRemote makes a local-path vault URL usable: a missing directory
// becomes a fresh bare repository. Network URLs are left alone.
func ensureRemote(url string) (string, error) {
	if !gitx.IsLocalPath(url) {
		return url, nil
	}
	p := strings.TrimPrefix(url, "file://")
	if strings.HasPrefix(p, "~/") {
		home, _ := os.UserHomeDir()
		p = filepath.Join(home, p[2:])
	}
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", err
	}
	if _, err := os.Stat(abs); errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(abs, 0o700); err != nil {
			return "", err
		}
		if _, err := gitx.Run(abs, "init", "--quiet", "--bare", "--initial-branch=main"); err != nil {
			return "", err
		}
		// let partial clones work against this local vault
		_, _ = gitx.Run(abs, "config", "uploadpack.allowFilter", "true")
		_, _ = gitx.Run(abs, "config", "receive.denyDeletes", "true")
		_, _ = gitx.Run(abs, "config", "receive.denyNonFastForwards", "true")
	}
	return abs, nil
}

// cloneVault makes a blob-less, checkout-less clone: the cheapest way to
// read manifests and only the bundles we need. Falls back to a plain
// no-checkout clone when the server refuses filters.
func cloneVault(url, dir string) error {
	_ = os.RemoveAll(dir)
	if err := os.MkdirAll(filepath.Dir(dir), 0o700); err != nil {
		return err
	}
	_, err := gitx.Run(filepath.Dir(dir), "clone", "--quiet", "--no-checkout", "--filter=blob:none", url, dir)
	if err == nil {
		return nil
	}
	_ = os.RemoveAll(dir)
	if _, err2 := gitx.Run(filepath.Dir(dir), "clone", "--quiet", "--no-checkout", url, dir); err2 != nil {
		return fmt.Errorf("clone vault: %w", err2)
	}
	return nil
}

// vaultBranch determines the vault's branch after a clone, adopting the
// single remote branch when the remote HEAD is unset, or "main" for an
// empty vault. It returns whether the vault is empty.
func vaultBranch(dir string) (string, bool, error) {
	if _, err := gitx.Run(dir, "rev-parse", "--verify", "-q", "HEAD"); err == nil {
		out, err := gitx.Run(dir, "symbolic-ref", "--short", "-q", "HEAD")
		if err != nil {
			return "", false, errors.New("vault clone has a detached HEAD")
		}
		return strings.TrimSpace(out), false, nil
	}
	out, _ := gitx.Run(dir, "for-each-ref", "--format=%(refname:short)", "refs/remotes/origin/")
	var branches []string
	for _, l := range strings.Split(strings.TrimSpace(out), "\n") {
		l = strings.TrimPrefix(l, "origin/")
		if l != "" && l != "HEAD" {
			branches = append(branches, l)
		}
	}
	switch len(branches) {
	case 0:
		if _, err := gitx.Run(dir, "symbolic-ref", "HEAD", "refs/heads/main"); err != nil {
			return "", false, err
		}
		return "main", true, nil
	case 1:
		b := branches[0]
		if _, err := gitx.Run(dir, "update-ref", "refs/heads/"+b, "refs/remotes/origin/"+b); err != nil {
			return "", false, err
		}
		if _, err := gitx.Run(dir, "symbolic-ref", "HEAD", "refs/heads/"+b); err != nil {
			return "", false, err
		}
		return b, false, nil
	default:
		return "", false, fmt.Errorf("vault has several branches (%s) and no default; set one on the host", strings.Join(branches, ", "))
	}
}

// syncCache brings the persistent cache clone to the remote's tip. It
// returns the branch name and whether the vault is empty.
func syncCache(url, cacheDir, knownBranch string) (string, bool, error) {
	if _, err := os.Stat(filepath.Join(cacheDir, ".git")); err != nil {
		if err := cloneVault(url, cacheDir); err != nil {
			return "", false, err
		}
		branch, empty, err := vaultBranch(cacheDir)
		if err != nil {
			return "", false, err
		}
		if !empty {
			if _, err := gitx.Run(cacheDir, "read-tree", "HEAD"); err != nil {
				return "", false, err
			}
		}
		return branch, empty, nil
	}
	branch := knownBranch
	if branch == "" {
		branch = "main"
	}
	_, _ = gitx.Run(cacheDir, "clean", "-fdxq")
	if _, err := gitx.Run(cacheDir, "fetch", "--quiet", "origin"); err != nil {
		return "", false, fmt.Errorf("fetch vault: %w", err)
	}
	if _, err := gitx.Run(cacheDir, "rev-parse", "--verify", "-q", "refs/remotes/origin/"+branch); err != nil {
		// remote still empty
		if _, err := gitx.Run(cacheDir, "symbolic-ref", "HEAD", "refs/heads/"+branch); err != nil {
			return "", false, err
		}
		_, _ = gitx.Run(cacheDir, "update-ref", "-d", "refs/heads/"+branch)
		_, _ = gitx.Run(cacheDir, "read-tree", "--empty")
		return branch, true, nil
	}
	if _, err := gitx.Run(cacheDir, "update-ref", "refs/heads/"+branch, "refs/remotes/origin/"+branch); err != nil {
		return "", false, err
	}
	if _, err := gitx.Run(cacheDir, "symbolic-ref", "HEAD", "refs/heads/"+branch); err != nil {
		return "", false, err
	}
	if _, err := gitx.Run(cacheDir, "read-tree", "HEAD"); err != nil {
		return "", false, err
	}
	return branch, false, nil
}

// commitPush adds the given vault-relative files, commits and pushes. The
// commit message and author are constant: they are visible to the host.
func commitPush(cacheDir, branch string, files []string) error {
	args := append([]string{"add", "--"}, files...)
	if _, err := gitx.Run(cacheDir, args...); err != nil {
		return err
	}
	if _, err := gitx.Run(cacheDir, "-c", "user.name=secretree", "-c", "user.email=secretree@localhost",
		"commit", "--quiet", "--no-verify", "-m", "backup"); err != nil {
		return err
	}
	if _, err := gitx.Run(cacheDir, "push", "--quiet", "origin", "HEAD:refs/heads/"+branch); err != nil {
		var ge *gitx.Error
		if errors.As(err, &ge) && (strings.Contains(ge.Stderr, "[rejected]") || strings.Contains(ge.Stderr, "non-fast-forward") || strings.Contains(ge.Stderr, "fetch first")) {
			return errPushRejected
		}
		return fmt.Errorf("push to vault: %w", err)
	}
	// forget the worktree copies; the index and HEAD already reflect them
	for _, f := range files {
		_ = os.Remove(filepath.Join(cacheDir, filepath.FromSlash(f)))
	}
	return nil
}
