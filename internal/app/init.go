package app

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/buildsnap-dev/secretree/internal/config"
	"github.com/buildsnap-dev/secretree/internal/crypt"
	"github.com/buildsnap-dev/secretree/internal/gitx"
	"github.com/buildsnap-dev/secretree/internal/keys"
	"github.com/buildsnap-dev/secretree/internal/keystore"
	"github.com/buildsnap-dev/secretree/internal/vault"
)

// InitOptions configures Init.
type InitOptions struct {
	Dir      string // source repository (default: cwd)
	VaultURL string
	Label    string
	KitIn    string // recovery kit to import (joining an existing vault on a new machine)
	KitOut   string // where to write the new recovery kit ("" = stdout)
	RepoID   string // adopt an existing chain instead of starting a new one
	Force    bool
	NoRemote bool   // do not add the "origin" remote / install the helper
	Push     bool   // push every branch and tag through the helper right away
	Remote   string // remote name (default origin)
	Name     string // this device's member name (default: hostname)
}

// Init prepares a repository for backups: keys in the key store, vault
// bootstrapped or joined, local config written, recovery kit printed.
func (a *App) Init(o InitOptions) error {
	if o.VaultURL == "" {
		return errors.New("--vault <git url or directory> is required")
	}
	work, gitDir, err := locateRepo(o.Dir)
	if err != nil {
		return err
	}
	paths := config.NewPaths(gitDir)
	if _, err := os.Stat(paths.Config); err == nil && !o.Force {
		return fmt.Errorf("already initialised (%s); use --force to re-initialise", paths.Config)
	}
	store, err := keystore.Open()
	if err != nil {
		return err
	}
	created, err := a.createHostRepo(&o.VaultURL)
	if err != nil {
		return err
	}
	url, err := ensureRemote(o.VaultURL)
	if err != nil {
		return err
	}
	branch, empty, err := syncCache(url, paths.Cache, "")
	if err != nil {
		return err
	}
	reader := &vault.Reader{Dir: paths.Cache}

	var kb *keys.Bundle
	var meta *vault.Meta
	newVault := false
	if empty {
		if o.KitIn != "" {
			return errors.New("the vault is empty but --from-recovery-kit was given; omit it to create a new vault")
		}
		newVault = true
		id, err := keys.NewVaultID()
		if err != nil {
			return err
		}
		if kb, err = keys.Generate(id); err != nil {
			return err
		}
		if err := store.Put(kb); err != nil {
			return err
		}
		if meta, err = a.bootstrapVault(reader, kb, branch, url, o.Name); err != nil {
			return err
		}
		if a.hostProtect != nil {
			a.hostProtect()
			a.hostProtect = nil
		}
	} else {
		if kb, meta, err = a.joinVault(store, reader, o.KitIn); err != nil {
			return err
		}
	}

	repoID := o.RepoID
	if repoID == "" {
		if repoID, err = keys.NewVaultID(); err != nil {
			return err
		}
	} else if !newVault && !reader.Exists(vault.RepoDir(repoID)) {
		return fmt.Errorf("repo id %s not found in the vault", repoID)
	}
	label := o.Label
	if label == "" {
		label = filepath.Base(work)
	}
	cfg := &config.Config{
		VaultURL:    url,
		VaultBranch: branch,
		VaultID:     meta.VaultID,
		RepoID:      repoID,
		Label:       label,
		FullEvery:   20,
		FullRatio:   1.0,
	}
	if err := config.Save(paths, cfg); err != nil {
		return err
	}
	a.logf("vault:   %s (id %s, branch %s)", url, meta.VaultID, branch)
	a.logf("repo:    %s (id %s)", label, repoID)
	a.logf("keys:    %s", store.Describe())
	a.logf("config:  %s", paths.Config)

	if created != "" {
		a.logf("host:    created %s (private, main protected)", created)
	}
	if newVault {
		kit, err := kb.RecoveryKit(url)
		if err != nil {
			return err
		}
		if o.KitOut != "" {
			if err := os.WriteFile(o.KitOut, []byte(kit), 0o600); err != nil {
				return err
			}
			a.logf("\nRecovery kit written to %s. PRINT IT, then delete the file.", o.KitOut)
		} else {
			a.logf("\nRecovery kit (print it; without it a lost machine means lost backups):\n")
			fmt.Fprint(a.Out, kit)
		}
		st, _ := config.LoadStatus(paths)
		st.KitPending = true
		_ = config.SaveStatus(paths, st)
		a.logf("\nWhen it is on paper, run: secretree kit --confirm   (status warns until then)")
		if o.KitOut != "" {
			a.logf("To print it now:        secretree kit --print %s", o.KitOut)
		}
	}
	if !o.NoRemote {
		remote := o.Remote
		if remote == "" {
			remote = "origin"
		}
		if err := a.wireRemote(work, remote, url); err != nil {
			a.logf("\nnote: %v", err)
		}
		if o.Push {
			a.logf("\npushing every branch and tag through the helper…")
			if err := a.pushAll(work, remote); err != nil {
				return err
			}
		} else {
			a.logf("\nNext: git push -u %s --all && git push %s --tags   (or: secretree backup)", remote, remote)
		}
	} else {
		a.logf("\nNext: secretree backup")
	}
	return nil
}

// wireRemote installs the helper and adds the secretree:: remote when the
// repository has no remote of that name yet.
func (a *App) wireRemote(work, remote, url string) error {
	pathEnv, err := ensureHelperInPath()
	if err != nil {
		return err
	}
	if !strings.Contains(os.Getenv("PATH"), filepath.Dir(exePath())) {
		a.logf("helper:  git-remote-secretree installed in %s; add that directory to your PATH (secretree install-helper --dir /usr/local/bin puts it somewhere already on it)", filepath.Dir(exePath()))
	} else {
		a.logf("helper:  git-remote-secretree ready")
	}
	_ = pathEnv
	if cur, err := gitx.Run(work, "remote", "get-url", remote); err == nil {
		cur = strings.TrimSpace(cur)
		if cur == "secretree::"+url {
			a.logf("remote:  %s already points at the vault", remote)
			return nil
		}
		return fmt.Errorf("remote %q already exists (%s); add the vault yourself: git remote add vault secretree::%s", remote, cur, url)
	}
	if _, err := gitx.Run(work, "remote", "add", remote, "secretree::"+url); err != nil {
		return err
	}
	a.logf("remote:  %s = secretree::%s", remote, url)
	return nil
}

func exePath() string {
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	if r, err := filepath.EvalSymlinks(exe); err == nil {
		return r
	}
	return exe
}

// pushAll pushes branches and tags through the helper with the helper
// reachable even when the binary's directory is not on PATH.
func (a *App) pushAll(work, remote string) error {
	pathEnv, err := ensureHelperInPath()
	if err != nil {
		return err
	}
	for _, args := range [][]string{{"push", "-u", remote, "--all"}, {"push", remote, "--tags"}} {
		cmd := exec.Command("git", args...)
		cmd.Dir = work
		cmd.Env = append(gitx.Env(), "PATH="+pathEnv)
		cmd.Stdout, cmd.Stderr = a.Out, a.Err
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("git %s: %w", strings.Join(args, " "), err)
		}
	}
	return nil
}

// createHostRepo turns "github:owner/name" or "gitlab:owner/name" into a
// freshly created private repository (via the gh / glab CLI) and rewrites
// the URL to its SSH form. Plain URLs and paths pass through untouched.
func (a *App) createHostRepo(url *string) (string, error) {
	var kind, slug string
	switch {
	case strings.HasPrefix(*url, "github:"):
		kind, slug = "github", strings.TrimPrefix(*url, "github:")
	case strings.HasPrefix(*url, "gitlab:"):
		kind, slug = "gitlab", strings.TrimPrefix(*url, "gitlab:")
	default:
		return "", nil
	}
	if !strings.Contains(slug, "/") {
		return "", fmt.Errorf("%s: expected owner/name", *url)
	}
	switch kind {
	case "github":
		if _, err := exec.LookPath("gh"); err != nil {
			return "", errors.New("github: the gh CLI is not installed (https://cli.github.com); or create the repository yourself and pass its URL")
		}
		out, err := exec.Command("gh", "repo", "create", slug, "--private", "--description", "secretree vault (ciphertext only)").CombinedOutput()
		if err != nil && !strings.Contains(string(out), "already exists") {
			return "", fmt.Errorf("gh repo create: %s", strings.TrimSpace(string(out)))
		}
		*url = "git@github.com:" + slug + ".git"
		a.hostProtect = func() {
			// force-push and deletion of main are refused by the host too
			body := `{"required_status_checks":null,"enforce_admins":false,"required_pull_request_reviews":null,"restrictions":null,"allow_force_pushes":false,"allow_deletions":false}`
			cmd := exec.Command("gh", "api", "-X", "PUT", "repos/"+slug+"/branches/main/protection", "--input", "-")
			cmd.Stdin = strings.NewReader(body)
			if out, err := cmd.CombinedOutput(); err != nil {
				a.logf("note: could not protect main on GitHub (%s); do it in the repository settings", strings.TrimSpace(string(out)))
			}
		}
		return "github.com/" + slug, nil
	default:
		if _, err := exec.LookPath("glab"); err != nil {
			return "", errors.New("gitlab: the glab CLI is not installed (https://gitlab.com/gitlab-org/cli); or create the project yourself and pass its URL")
		}
		out, err := exec.Command("glab", "repo", "create", slug, "--private", "--description", "secretree vault (ciphertext only)").CombinedOutput()
		if err != nil && !strings.Contains(string(out), "already") {
			return "", fmt.Errorf("glab repo create: %s", strings.TrimSpace(string(out)))
		}
		*url = "git@gitlab.com:" + slug + ".git"
		// GitLab protects the default branch (no force-push) out of the box
		return "gitlab.com/" + slug, nil
	}
}

// bootstrapVault writes README, vault.json and its signature as the first
// commit of an empty vault.
func (a *App) bootstrapVault(reader *vault.Reader, kb *keys.Bundle, branch, url, name string) (*vault.Meta, error) {
	recipient, err := kb.Recipient()
	if err != nil {
		return nil, err
	}
	if name == "" {
		name, _ = os.Hostname()
	}
	signerLine, err := kb.AllowedSignersLine(name)
	if err != nil {
		return nil, err
	}
	fp, _ := kb.Fingerprint()
	meta := &vault.Meta{
		Format:         vault.FormatVault,
		VaultID:        kb.VaultID,
		Created:        time.Now().UTC().Truncate(time.Second),
		Recipients:     []string{recipient},
		AllowedSigners: []string{signerLine},
		Members:        []vault.Member{{Name: name, Recipient: recipient, SignerFingerprint: fp, Added: time.Now().UTC().Truncate(time.Second)}},
	}
	data, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return nil, err
	}
	data = append(data, '\n')
	signer, err := kb.Signer()
	if err != nil {
		return nil, err
	}
	sig, err := crypt.Sign(data, signer)
	if err != nil {
		return nil, err
	}
	dir := reader.Dir
	files := map[string][]byte{
		vault.ReadmeFile:        []byte(vault.Readme),
		vault.MetaFile:          data,
		vault.MetaFile + ".sig": sig,
	}
	var names []string
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), content, 0o644); err != nil {
			return nil, err
		}
		names = append(names, name)
	}
	if err := commitPush(dir, branch, names); err != nil {
		return nil, err
	}
	if _, err := gitx.Run(dir, "read-tree", "HEAD"); err != nil {
		return nil, err
	}
	return meta, nil
}

// joinVault loads the keys for an existing vault, importing a recovery kit
// when given, and verifies vault.json against our signing key.
func (a *App) joinVault(store keystore.Store, reader *vault.Reader, kitIn string) (*keys.Bundle, *vault.Meta, error) {
	raw, err := reader.ReadFile(vault.MetaFile)
	if err != nil {
		return nil, nil, fmt.Errorf("the remote has commits but no %s: not a secretree vault", vault.MetaFile)
	}
	var m vault.Meta
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, nil, fmt.Errorf("vault.json: %w", err)
	}
	var kb *keys.Bundle
	if kitIn != "" {
		text, err := os.ReadFile(kitIn)
		if err != nil {
			return nil, nil, err
		}
		kb, _, err = keys.ParseRecoveryKit(string(text))
		if err != nil {
			return nil, nil, err
		}
		if kb.VaultID != m.VaultID {
			return nil, nil, fmt.Errorf("recovery kit is for vault %s but the remote holds vault %s", kb.VaultID, m.VaultID)
		}
		if err := store.Put(kb); err != nil {
			return nil, nil, err
		}
		a.logf("keys from recovery kit stored in %s", store.Describe())
	} else {
		kb, err = store.Get(m.VaultID)
		if errors.Is(err, keystore.ErrNotFound) {
			return nil, nil, fmt.Errorf("vault %s exists but its keys are not in the %s; pass --from-recovery-kit <file>, or `secretree join` on a new device", m.VaultID, store.Describe())
		}
		if err != nil {
			return nil, nil, err
		}
	}
	pub, err := kb.PublicKey()
	if err != nil {
		return nil, nil, err
	}
	meta, _, err := vault.LoadMeta(reader, pub)
	if err != nil {
		return nil, nil, err
	}
	return kb, meta, nil
}

// autoInit configures a repository the first time the remote helper runs
// in it (typically during `git clone secretree::...`).
func (a *App) autoInit(gitDir, helperURL string) error {
	vaultURL, repoID := ParseHelperURL(helperURL)
	url, err := ensureRemote(vaultURL)
	if err != nil {
		return err
	}
	paths := config.NewPaths(gitDir)
	store, err := keystore.Open()
	if err != nil {
		return err
	}
	branch, empty, err := syncCache(url, paths.Cache, "")
	if err != nil {
		return err
	}
	if empty {
		return fmt.Errorf("%s is an empty vault; run `secretree init --vault %s` in a repository first", url, vaultURL)
	}
	reader := &vault.Reader{Dir: paths.Cache}
	kb, meta, err := a.joinVault(store, reader, "")
	if err != nil {
		return err
	}
	ids, err := reader.ListRepos()
	if err != nil {
		return err
	}
	label := filepath.Base(filepath.Dir(gitDir))
	switch {
	case repoID != "":
		found := false
		for _, id := range ids {
			if id == repoID {
				found = true
			}
		}
		if !found {
			return fmt.Errorf("repo id %s not found in the vault (available: %s)", repoID, strings.Join(ids, ", "))
		}
	case len(ids) == 1:
		repoID = ids[0]
	case len(ids) == 0:
		return fmt.Errorf("the vault holds no repositories yet; run `secretree init --vault %s` in a repository first", vaultURL)
	default:
		return fmt.Errorf("the vault holds several repositories; use secretree::%s#<repo-id> (available: %s)", vaultURL, strings.Join(ids, ", "))
	}
	if id, err := kb.Identity(); err == nil {
		if pub, err := kb.PublicKey(); err == nil {
			if _, signers, err := vault.LoadMeta(reader, pub); err == nil {
				if c, err := vault.LoadChain(reader, meta.VaultID, repoID, id, signers); err == nil && c.Last() != nil && !c.Last().Opaque() && c.Last().Manifest.Source.Label != "" {
					label = c.Last().Manifest.Source.Label
				}
			}
		}
	}
	cfg := &config.Config{VaultURL: url, VaultBranch: branch, VaultID: meta.VaultID, RepoID: repoID, Label: label, FullEvery: 20, FullRatio: 1.0}
	return config.Save(paths, cfg)
}
