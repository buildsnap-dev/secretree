package app

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"

	"github.com/buildsnap-dev/secretree/internal/demo"
)

// Demo runs the full walkthrough in a throw-away directory with a file key
// store: two devices, a vault, a pull request, a review agent, CI, merge,
// deploy, share, backup, restore, a tamper test, and the UI at the end.
func (a *App) Demo(dir string, clean bool) error {
	if runtime.GOOS == "windows" {
		return errors.New("the demo needs a POSIX shell; run it in WSL")
	}
	if dir == "" {
		dir = filepath.Join(os.TempDir(), "secretree-demo")
	}
	script := filepath.Join(os.TempDir(), "secretree-demo-tour.sh")
	if err := os.WriteFile(script, []byte(demo.Script), 0o700); err != nil {
		return err
	}
	defer os.Remove(script)
	args := []string{script}
	if clean {
		args = append(args, "--clean")
	}
	cmd := exec.Command("/bin/sh", args...)
	cmd.Env = append(os.Environ(), "SECRETREE_TOUR_DIR="+dir, "SECRETREE_BIN="+exePath())
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, a.Out, a.Err
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("demo failed: %w", err)
	}
	if !clean {
		a.logf("\nThe demo lives in %s and its UI is running. Remove it with: secretree demo --clean", dir)
	}
	return nil
}
