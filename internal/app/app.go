// Package app implements the secretree commands on top of the lower-level
// packages. Every command is a method on App so tests can drive them
// in-process with a captured output.
package app

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"

	"filippo.io/age"
	"golang.org/x/crypto/ssh"

	"github.com/buildsnap-dev/secretree/internal/config"
	"github.com/buildsnap-dev/secretree/internal/gitx"
	"github.com/buildsnap-dev/secretree/internal/keys"
	"github.com/buildsnap-dev/secretree/internal/keystore"
)

// Version is stamped into manifests and printed by `secretree version`.
// Release builds set it through ldflags; a binary from `go install
// …@v1.2.3` picks the version up from the module's build info; a plain
// `go build` from a checkout stays "dev".
var Version = "dev"

func init() {
	if Version != "dev" {
		return // set at link time
	}
	bi, ok := debug.ReadBuildInfo()
	if !ok || bi.Main.Version == "" || bi.Main.Version == "(devel)" {
		return
	}
	Version = strings.TrimPrefix(bi.Main.Version, "v")
}

// App carries output streams and options shared by all commands.
type App struct {
	Out     io.Writer
	Err     io.Writer
	Verbose bool

	hostProtect func() // set by createHostRepo, run once the vault branch exists
}

func (a *App) logf(format string, args ...any) {
	fmt.Fprintf(a.Out, format+"\n", args...)
}

func (a *App) debugf(format string, args ...any) {
	if a.Verbose {
		fmt.Fprintf(a.Err, "  "+format+"\n", args...)
	}
}

// repo is an initialised source repository with its keys loaded.
type repo struct {
	Work   string
	GitDir string
	Paths  config.Paths
	Cfg    *config.Config
	Keys   *keys.Bundle
	Store  keystore.Store

	identity *age.X25519Identity
	signer   ssh.Signer

	acceptRollback bool // repair: proceed although the host lost generations
}

func locateRepo(dir string) (work, gitDir string, err error) {
	if dir == "" {
		dir, err = os.Getwd()
		if err != nil {
			return "", "", err
		}
	}
	work, err = gitx.TopLevel(dir)
	if err != nil {
		return "", "", fmt.Errorf("%s is not inside a git work tree", dir)
	}
	gitDir, err = gitx.GitDir(work)
	if err != nil {
		return "", "", err
	}
	return work, gitDir, nil
}

// openRepo loads config and keys for the repository containing dir.
func (a *App) openRepo(dir string) (*repo, error) {
	work, gitDir, err := locateRepo(dir)
	if err != nil {
		return nil, err
	}
	return a.openRepoAt(work, gitDir)
}

// openRepoGitDir opens a repository by its git dir (remote-helper mode,
// where a work tree may not exist yet).
func (a *App) openRepoGitDir(gitDir string) (*repo, error) {
	return a.openRepoAt(filepath.Dir(gitDir), gitDir)
}

func (a *App) openRepoAt(work, gitDir string) (*repo, error) {
	var err error
	paths := config.NewPaths(gitDir)
	cfg, err := config.Load(paths)
	if err != nil {
		return nil, err
	}
	store, err := keystore.Open()
	if err != nil {
		return nil, err
	}
	kb, err := store.Get(cfg.VaultID)
	if errors.Is(err, keystore.ErrNotFound) {
		return nil, fmt.Errorf("keys for vault %s are not in the %s; run: secretree init --from-recovery-kit <file> --vault %s", cfg.VaultID, store.Describe(), cfg.VaultURL)
	}
	if err != nil {
		return nil, err
	}
	r := &repo{Work: work, GitDir: gitDir, Paths: paths, Cfg: cfg, Keys: kb, Store: store}
	if r.identity, err = kb.Identity(); err != nil {
		return nil, err
	}
	if r.signer, err = kb.Signer(); err != nil {
		return nil, err
	}
	return r, nil
}

// lock takes an exclusive advisory lock so scheduled and manual runs never
// overlap. The returned func releases it.
func (r *repo) lock() (func(), error) {
	if err := os.MkdirAll(r.Paths.Root, 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(r.Paths.Root, "lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := flock(f); err != nil {
		f.Close()
		return nil, errors.New("another secretree run is in progress for this repository")
	}
	return func() {
		_ = funlock(f)
		f.Close()
	}, nil
}

// tmpDir creates a private scratch directory under .git/secretree/tmp.
// Plaintext bundles live here briefly; the directory is 0700 and removed
// by the caller. A RAM-backed location is a planned improvement.
func (r *repo) tmpDir(name string) (string, func(), error) {
	if err := os.MkdirAll(r.Paths.Tmp, 0o700); err != nil {
		return "", nil, err
	}
	d, err := os.MkdirTemp(r.Paths.Tmp, name+"-")
	if err != nil {
		return "", nil, err
	}
	return d, func() { _ = os.RemoveAll(d) }, nil
}

func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}
