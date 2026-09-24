package app

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/buildsnap-dev/secretree/internal/collab"
	"github.com/buildsnap-dev/secretree/internal/gitx"
)

// DeployOptions configures DeployAgent.
type DeployOptions struct {
	Dir          string        // a clone made with `secretree clone`
	Branch       string        // branch to deploy (default main)
	To           string        // target directory (exported tree, no .git)
	Cmd          string        // run after export, in To (e.g. "systemctl restart app")
	RequireCheck string        // deploy only commits with this check green (default "ci"; "" = none)
	Interval     time.Duration // poll interval (default 60s)
	Once         bool
}

// DeployAgent is pull-based CD: it runs on the target host, watches the
// encrypted remote, and when the branch tip changes and policy passes it
// exports the tree, runs a command, and records a signed deploy event.
// The target needs no inbound access and CI holds no production keys.
func (a *App) DeployAgent(o DeployOptions) error {
	if o.To == "" {
		return errors.New("--to <dir> is required")
	}
	if o.Branch == "" {
		o.Branch = "main"
	}
	if o.Interval == 0 {
		o.Interval = 60 * time.Second
	}
	for {
		deployed, err := a.deployPass(o)
		if err != nil {
			a.logf("deploy: %v", err)
		} else if deployed != "" {
			a.logf("deploy: %s is live at %s", short(deployed), o.To)
		}
		if o.Once {
			return err
		}
		time.Sleep(o.Interval)
	}
}

func (a *App) deployPass(o DeployOptions) (string, error) {
	c, err := a.openPR(o.Dir)
	if err != nil {
		return "", err
	}
	sha := c.baseSHA(&collab.PullRequest{Base: o.Branch})
	if sha == "" {
		return "", fmt.Errorf("branch %s not found", o.Branch)
	}
	marker := filepath.Join(o.To, ".secretree-deployed")
	if cur, err := os.ReadFile(marker); err == nil && strings.TrimSpace(string(cur)) == sha {
		return "", nil
	}
	if o.RequireCheck != "" {
		e, ok := collab.Checks(c.events, sha)[o.RequireCheck]
		if !ok || e.Status != collab.StatusSuccess {
			a.debugf("deploy: waiting for check %q on %s", o.RequireCheck, short(sha))
			return "", nil
		}
	}
	if err := os.MkdirAll(o.To, 0o755); err != nil {
		return "", err
	}
	tarPath := filepath.Join(os.TempDir(), "secretree-deploy-"+short(sha)+".tar")
	if err := gitx.RunToFile(c.r.Work, tarPath, "archive", "--format=tar", sha); err != nil {
		return "", err
	}
	defer os.Remove(tarPath)
	untar := exec.Command("tar", "-xf", tarPath, "-C", o.To)
	if out, err := untar.CombinedOutput(); err != nil {
		return "", fmt.Errorf("export: %s", strings.TrimSpace(string(out)))
	}
	status, summary := collab.StatusSuccess, "exported"
	if o.Cmd != "" {
		run := gitx.ShellCommand(o.Cmd)
		run.Dir = o.To
		run.Env = append(gitx.Env(), "SECRETREE_COMMIT="+sha)
		out, err := run.CombinedOutput()
		if err != nil {
			status, summary = collab.StatusFailure, fmt.Sprintf("%s failed: %v: %s", o.Cmd, err, truncate(strings.TrimSpace(string(out)), 200))
		} else {
			summary = fmt.Sprintf("exported and ran %s", o.Cmd)
		}
	}
	if status == collab.StatusSuccess {
		if err := os.WriteFile(marker, []byte(sha+"\n"), 0o644); err != nil {
			return "", err
		}
	}
	host, _ := os.Hostname()
	e := &collab.Event{Kind: collab.KindDeploy, Commit: sha, Name: o.Branch, Status: status, Summary: summary, Target: host + ":" + o.To}
	if err := c.append(e); err != nil {
		return "", err
	}
	if status != collab.StatusSuccess {
		return "", errors.New(summary)
	}
	return sha, nil
}
