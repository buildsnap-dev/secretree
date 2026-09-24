package app

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/buildsnap-dev/secretree/internal/config"
	"github.com/buildsnap-dev/secretree/internal/gitx"
	"github.com/buildsnap-dev/secretree/internal/keystore"
	"github.com/buildsnap-dev/secretree/internal/vault"
)

type check struct {
	name, detail, fix string
	ok                bool
	warn              bool
}

// Doctor runs every check a support request would start with and prints
// the fix next to each failure.
func (a *App) Doctor(dir string) error {
	var cs []check
	add := func(name string, ok bool, detail, fix string) {
		cs = append(cs, check{name: name, ok: ok, detail: detail, fix: fix})
	}
	warn := func(name, detail, fix string) {
		cs = append(cs, check{name: name, ok: true, warn: true, detail: detail, fix: fix})
	}

	// git
	if out, err := gitx.Run(".", "--version"); err == nil {
		v := strings.TrimSpace(strings.TrimPrefix(out, "git version "))
		add("git", true, v, "")
	} else {
		add("git", false, "not found", "install git 2.20 or newer")
	}

	// helper
	exe := exePath()
	if p, err := exec.LookPath(HelperName); err == nil {
		target, _ := filepath.EvalSymlinks(p)
		if target == exe || target == "" {
			add("git helper", true, p, "")
		} else {
			warn("git helper", p+" is not this binary ("+exe+")", "secretree install-helper --dir "+filepath.Dir(p))
		}
	} else {
		add("git helper", false, HelperName+" not on PATH", "secretree install-helper --dir /usr/local/bin   (any directory on PATH)")
	}

	// key store
	store, err := keystore.Open()
	if err != nil {
		add("key store", false, err.Error(), "unset SECRETREE_KEYSTORE or set it to keychain, secret-service or file")
	} else {
		add("key store", true, store.Describe(), "")
	}

	// repository (optional)
	work, gitDir, err := locateRepo(dir)
	if err != nil {
		warn("repository", "not inside a git work tree; repository checks skipped", "")
		return a.printChecks(cs)
	}
	paths := config.NewPaths(gitDir)
	cfg, err := config.Load(paths)
	if err != nil {
		add("repository", false, work+" is not initialised", "secretree init --vault <url>   or   secretree clone <vault>")
		return a.printChecks(cs)
	}
	add("repository", true, fmt.Sprintf("%s (label %s, repo %s)", work, cfg.Label, cfg.RepoID), "")

	// keys for this vault
	var r *repo
	if store != nil {
		if _, err := store.Get(cfg.VaultID); err != nil {
			add("vault keys", false, "no keys for vault "+cfg.VaultID+" in "+store.Describe(), "secretree init --from-recovery-kit <file> --vault "+cfg.VaultURL+"   or   secretree join --vault "+cfg.VaultURL)
		} else {
			add("vault keys", true, "present for vault "+cfg.VaultID, "")
			r, _ = a.openRepoAt(work, gitDir)
		}
	}

	// remote
	if remote := secretreeRemote(work); remote != "" {
		add("git remote", true, remote+" = secretree::"+cfg.VaultURL, "")
	} else {
		warn("git remote", "no secretree:: remote (backup-only repository)", "git remote add origin secretree::"+cfg.VaultURL)
	}

	// vault reachable and chain verified
	if r != nil {
		start := time.Now()
		vs, err := a.loadVault(r)
		if err != nil {
			add("vault", false, err.Error(), "secretree verify --quick   shows which generation fails")
		} else {
			n := 0
			if vs.Chain.Last() != nil {
				n = vs.Chain.Last().Num
			}
			add("vault", true, fmt.Sprintf("%s: %d generation(s), chain verified in %s", cfg.VaultURL, n, time.Since(start).Round(time.Millisecond)), "")
			opaque := len(vs.Chain.Gens) - vs.Chain.Readable()
			if opaque > 0 {
				warn("vault", fmt.Sprintf("%d generation(s) predate this key and are not readable by it (expected for members added later)", opaque), "")
			}
			_ = vault.GenName
		}
	}

	// status: kit, proof
	st, _ := config.LoadStatus(paths)
	if st != nil {
		if st.KitPending && st.KitConfirmed == nil {
			add("recovery kit", false, "created here, not confirmed as printed", "secretree kit --print <file>; secretree kit --confirm")
		} else {
			add("recovery kit", true, "confirmed or not created on this device", "")
		}
		switch {
		case st.LastGeneration == 0:
			warn("restore proof", "no backup yet", "secretree backup")
		case st.LastProofGeneration < st.LastGeneration && secretreeRemote(work) == "":
			add("restore proof", false, fmt.Sprintf("generation %06d not proven", st.LastGeneration), "secretree verify")
		default:
			add("restore proof", true, ago(st.LastProof, st.LastProofGeneration), "")
		}
		if st.LastError != "" {
			warn("last error", st.LastError, "")
		}
	}

	// policy and pipeline
	if _, err := os.Stat(filepath.Join(work, ".secretree", "policy.json")); err == nil {
		add("review policy", true, ".secretree/policy.json present", "")
	} else {
		warn("review policy", "none; merges need no approvals or checks", "secretree policy --approvals 1 --checks ci")
	}
	if isExecutable(filepath.Join(work, ".secretree", "ci")) || hasMakeTarget(work, "ci") {
		add("pipeline", true, ".secretree/ci or make ci found", "")
	} else {
		warn("pipeline", "no .secretree/ci and no `ci` make target; runners have nothing to run", "add .secretree/ci")
	}

	// UI
	if conn, err := net.DialTimeout("tcp", DefaultUIAddr, 300*time.Millisecond); err == nil {
		conn.Close()
		add("local ui", true, "listening on http://"+DefaultUIAddr, "")
	} else {
		warn("local ui", "not running", "secretree ui --install   (or: secretree ui --open)")
	}
	return a.printChecks(cs)
}

func (a *App) printChecks(cs []check) error {
	failed := 0
	for _, c := range cs {
		mark := "ok  "
		switch {
		case !c.ok:
			mark = "FAIL"
			failed++
		case c.warn:
			mark = "note"
		}
		a.logf("%s  %-14s %s", mark, c.name, c.detail)
		if c.fix != "" && (!c.ok || c.warn) {
			a.logf("      %-14s → %s", "", c.fix)
		}
	}
	if failed > 0 {
		return fmt.Errorf("%d check(s) failed", failed)
	}
	return nil
}
