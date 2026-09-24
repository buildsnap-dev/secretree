package app

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/buildsnap-dev/secretree/internal/config"
	"github.com/buildsnap-dev/secretree/internal/keystore"
)

// Status prints the local view: what was backed up, what was proven.
func (a *App) Status(dir string) error {
	work, gitDir, err := locateRepo(dir)
	if err != nil {
		return err
	}
	paths := config.NewPaths(gitDir)
	cfg, err := config.Load(paths)
	if err != nil {
		return err
	}
	st, err := config.LoadStatus(paths)
	if err != nil {
		return err
	}
	store, _ := keystore.Open()
	keysOK := "missing"
	if store != nil {
		if _, err := store.Get(cfg.VaultID); err == nil {
			keysOK = "present"
		}
	}
	a.logf("repository:      %s (%s, id %s)", work, cfg.Label, cfg.RepoID)
	a.logf("vault:           %s (id %s, branch %s)", cfg.VaultURL, cfg.VaultID, cfg.VaultBranch)
	if store != nil {
		a.logf("keys:            %s in %s", keysOK, store.Describe())
	}
	a.logf("generations:     %d (%s on the remote)", st.Generations, humanBytes(st.ChainBytes))
	a.logf("last backup:     %s", ago(st.LastBackup, st.LastGeneration))
	a.logf("last proven:     %s", ago(st.LastProof, st.LastProofGeneration))
	if len(cfg.State.Include) > 0 || cfg.State.PreHook != "" {
		a.logf("state archive:   %d include path(s), pre-hook %q", len(cfg.State.Include), cfg.State.PreHook)
	} else {
		a.logf("state archive:   none configured")
	}
	if st.LastError != "" {
		a.logf("LAST ERROR:      %s (%s)", st.LastError, ago(st.LastErrorTime, 0))
	}
	if st.KitPending && st.KitConfirmed == nil {
		a.logf("\nWARNING: the recovery kit of this vault has not been confirmed as printed. Without it a lost machine means lost backups. secretree kit --confirm")
	}
	switch {
	case st.LastGeneration == 0:
		a.logf("\nno backup yet: run secretree backup")
	case st.LastProofGeneration < st.LastGeneration && secretreeRemote(work) == "":
		a.logf("\nWARNING: generation %06d has NOT been proven restorable; run secretree verify", st.LastGeneration)
	case st.LastProofGeneration < st.LastGeneration:
		a.logf("\nnote: pushes are verified on every fetch; for a full rebuild proof of generation %06d run secretree verify", st.LastGeneration)
	}
	return nil
}

func ago(t *time.Time, gen int) string {
	if t == nil {
		return "never"
	}
	d := time.Since(*t).Round(time.Minute)
	s := fmt.Sprintf("%s (%s ago)", t.Local().Format("2006-01-02 15:04"), d)
	if gen > 0 {
		s = fmt.Sprintf("generation %06d, %s", gen, s)
	}
	return s
}

// Kit manages the recovery kit: print it, or confirm it is on paper.
func (a *App) Kit(dir string, printPath string, confirm bool) error {
	_, gitDir, err := locateRepo(dir)
	if err != nil {
		return err
	}
	paths := config.NewPaths(gitDir)
	if printPath != "" {
		if _, err := os.Stat(printPath); err != nil {
			return err
		}
		if lp, err := exec.LookPath("lp"); err == nil {
			if out, err := exec.Command(lp, printPath).CombinedOutput(); err == nil {
				a.logf("sent to the default printer: %s", strings.TrimSpace(string(out)))
			} else {
				a.logf("lp failed (%s); opening the file instead", strings.TrimSpace(string(out)))
				openBrowser("file://" + printPath)
			}
		} else {
			openBrowser("file://" + printPath)
		}
		a.logf("after printing: secretree kit --confirm, then delete %s", printPath)
	}
	if confirm {
		st, err := config.LoadStatus(paths)
		if err != nil {
			return err
		}
		now := time.Now().UTC()
		st.KitConfirmed = &now
		st.KitPending = false
		if err := config.SaveStatus(paths, st); err != nil {
			return err
		}
		a.logf("recovery kit confirmed as printed on %s", now.Format("2006-01-02"))
	}
	if printPath == "" && !confirm {
		a.logf("usage: secretree kit --print <file> | --confirm")
	}
	return nil
}
