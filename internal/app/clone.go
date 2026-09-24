package app

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/buildsnap-dev/secretree/internal/keys"
	"github.com/buildsnap-dev/secretree/internal/keystore"
)

// HelperName is the executable name git looks for.
const HelperName = "git-remote-secretree"

// CloneOptions configures Clone.
type CloneOptions struct {
	VaultURL string
	Dir      string
	RepoID   string
	KitIn    string
}

// Clone imports keys if given, makes sure the helper is reachable, and runs
// `git clone secretree::<vault>#<repo>`.
func (a *App) Clone(o CloneOptions) error {
	if o.VaultURL == "" {
		return errors.New("vault URL is required")
	}
	if o.KitIn != "" {
		text, err := os.ReadFile(o.KitIn)
		if err != nil {
			return err
		}
		kb, _, err := keys.ParseRecoveryKit(string(text))
		if err != nil {
			return err
		}
		store, err := keystore.Open()
		if err != nil {
			return err
		}
		if err := store.Put(kb); err != nil {
			return err
		}
		a.logf("keys from recovery kit stored in %s", store.Describe())
	}
	url, err := ensureRemote(o.VaultURL)
	if err != nil {
		return err
	}
	pathEnv, err := ensureHelperInPath()
	if err != nil {
		return err
	}
	spec := "secretree::" + url
	if o.RepoID != "" {
		spec += "#" + o.RepoID
	}
	args := []string{"clone", spec}
	if o.Dir != "" {
		args = append(args, o.Dir)
	}
	cmd := exec.Command("git", args...)
	cmd.Env = append(os.Environ(), "PATH="+pathEnv)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, a.Out, a.Err
	return cmd.Run()
}

// ensureHelperInPath returns a PATH in which git can find the helper,
// installing a symlink next to our own executable if needed.
func ensureHelperInPath() (string, error) {
	path := os.Getenv("PATH")
	if _, err := exec.LookPath(HelperName); err == nil {
		return path, nil
	}
	dir, err := InstallHelper("")
	if err != nil {
		return "", err
	}
	return dir + string(os.PathListSeparator) + path, nil
}

// InstallHelper symlinks git-remote-secretree to this executable in dir
// (default: the executable's own directory) and returns the directory.
func InstallHelper(dir string) (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	if exe, err = filepath.EvalSymlinks(exe); err != nil {
		return "", err
	}
	if dir == "" {
		dir = filepath.Dir(exe)
	}
	link := filepath.Join(dir, HelperName)
	if target, err := os.Readlink(link); err == nil && target == exe {
		return dir, nil
	}
	if runtime.GOOS == "windows" {
		link += ".exe"
	}
	_ = os.Remove(link)
	if runtime.GOOS != "windows" {
		if err := os.Symlink(exe, link); err == nil {
			return dir, nil
		}
	}
	// no symlinks (Windows, some filesystems): copy the executable
	src, err := os.Open(exe)
	if err != nil {
		return "", err
	}
	defer src.Close()
	dst, err := os.OpenFile(link, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		return "", fmt.Errorf("install helper: %w", err)
	}
	if _, err := io.Copy(dst, src); err != nil {
		dst.Close()
		return "", err
	}
	return dir, dst.Close()
}

// InstallHelperCmd is the user-facing installer.
func (a *App) InstallHelperCmd(dir string) error {
	d, err := InstallHelper(dir)
	if err != nil {
		return err
	}
	a.logf("%s installed in %s", HelperName, d)
	inPath := false
	for _, p := range strings.Split(os.Getenv("PATH"), string(os.PathListSeparator)) {
		if p == d {
			inPath = true
		}
	}
	if !inPath {
		a.logf("note: %s is not in your PATH; add it so git can find the helper", d)
	}
	a.logf("usage: git clone secretree::<vault-url>[#<repo-id>]   or   git remote add origin secretree::<vault-url>")
	return nil
}
