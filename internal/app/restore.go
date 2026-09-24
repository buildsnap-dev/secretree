package app

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/buildsnap-dev/secretree/internal/archive"
	"github.com/buildsnap-dev/secretree/internal/config"
	"github.com/buildsnap-dev/secretree/internal/gitx"
	"github.com/buildsnap-dev/secretree/internal/keys"
	"github.com/buildsnap-dev/secretree/internal/keystore"
	"github.com/buildsnap-dev/secretree/internal/vault"
)

// RestoreOptions configures Restore.
type RestoreOptions struct {
	VaultURL   string
	RepoID     string // "" = the only repo in the vault, or list them
	Generation int    // 0 = latest
	To         string // target directory (must not exist)
	KitIn      string // recovery kit; otherwise keys come from the key store
	NoState    bool
}

// Restore rebuilds a repository from the vault into a new directory and
// initialises it so backups can continue into the same chain.
func (a *App) Restore(o RestoreOptions) error {
	if o.VaultURL == "" || o.To == "" {
		return errors.New("--vault and --to are required")
	}
	if _, err := os.Stat(o.To); err == nil {
		return fmt.Errorf("%s already exists; restore into a new directory", o.To)
	}
	url, err := ensureRemote(o.VaultURL)
	if err != nil {
		return err
	}
	parent := filepath.Dir(o.To)
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return err
	}
	tmp, err := os.MkdirTemp(parent, ".secretree-restore-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)

	dir := filepath.Join(tmp, "vault")
	if err := cloneVault(url, dir); err != nil {
		return err
	}
	reader := &vault.Reader{Dir: dir}
	raw, err := reader.ReadFile(vault.MetaFile)
	if err != nil {
		return err
	}
	var m vault.Meta
	if err := json.Unmarshal(raw, &m); err != nil {
		return err
	}
	store, err := keystore.Open()
	if err != nil {
		return err
	}
	var kb *keys.Bundle
	if o.KitIn != "" {
		text, err := os.ReadFile(o.KitIn)
		if err != nil {
			return err
		}
		if kb, _, err = keys.ParseRecoveryKit(string(text)); err != nil {
			return err
		}
		if kb.VaultID != m.VaultID {
			return fmt.Errorf("recovery kit is for vault %s but the remote holds vault %s", kb.VaultID, m.VaultID)
		}
		if err := store.Put(kb); err != nil {
			return err
		}
	} else {
		kb, err = store.Get(m.VaultID)
		if errors.Is(err, keystore.ErrNotFound) {
			return fmt.Errorf("keys for vault %s are not in the %s; pass --from-recovery-kit <file>", m.VaultID, store.Describe())
		}
		if err != nil {
			return err
		}
	}
	identity, err := kb.Identity()
	if err != nil {
		return err
	}
	pub, _ := kb.PublicKey()
	meta, signers, err := vault.LoadMeta(reader, pub)
	if err != nil {
		return err
	}
	repoID := o.RepoID
	if repoID == "" {
		ids, err := reader.ListRepos()
		if err != nil {
			return err
		}
		switch len(ids) {
		case 0:
			return errors.New("the vault holds no repositories")
		case 1:
			repoID = ids[0]
		default:
			var lines []string
			for _, id := range ids {
				label := "?"
				if c, err := vault.LoadChain(reader, meta.VaultID, id, identity, signers); err == nil && c.Last() != nil && !c.Last().Opaque() {
					label = c.Last().Manifest.Source.Label
				}
				lines = append(lines, fmt.Sprintf("  %s  %s", id, label))
			}
			return fmt.Errorf("the vault holds several repositories; pass --repo-id:\n%s", strings.Join(lines, "\n"))
		}
	}
	chain, err := vault.LoadChain(reader, meta.VaultID, repoID, identity, signers)
	if err != nil {
		return err
	}
	if chain.Last() == nil {
		return fmt.Errorf("repo %s has no generations", repoID)
	}
	target := o.Generation
	if target == 0 {
		target = chain.Last().Num
	}
	bare, g, err := vault.Rebuild(reader, chain, target, identity, filepath.Join(tmp, "rebuild"), a.debugf)
	if err != nil {
		return err
	}
	// turn the bare repo into a working repo at o.To
	if err := os.MkdirAll(o.To, 0o755); err != nil {
		return err
	}
	if err := os.Rename(bare, filepath.Join(o.To, ".git")); err != nil {
		return err
	}
	if _, err := gitx.Run(o.To, "config", "core.bare", "false"); err != nil {
		return err
	}
	if _, err := gitx.Run(o.To, "reset", "--hard", "--quiet"); err != nil {
		return err
	}
	a.logf("repository restored to %s at generation %06d (%d refs, HEAD %s)", o.To, target, len(g.Manifest.Refs), g.Manifest.Source.Head)

	if !o.NoState {
		stateFile, enc, err := vault.ExtractState(reader, repoID, g, identity, tmp)
		if err != nil {
			return err
		}
		if stateFile != "" {
			n, err := archive.Unpack(stateFile, enc, o.To)
			if err != nil {
				return fmt.Errorf("state archive: %w", err)
			}
			a.logf("state archive unpacked: %d files", n)
		}
	}

	// keep backing up into the same chain from the restored copy
	gitDir := filepath.Join(o.To, ".git")
	paths := config.NewPaths(gitDir)
	cfg := &config.Config{VaultURL: url, VaultID: meta.VaultID, RepoID: repoID, Label: g.Manifest.Source.Label, FullEvery: 20, FullRatio: 1.0}
	if b, _, err := vaultBranch(dir); err == nil {
		cfg.VaultBranch = b
	}
	if err := config.Save(paths, cfg); err != nil {
		return err
	}
	st := &config.Status{LastGeneration: chain.Last().Num, Generations: len(chain.Gens), ChainBytes: chain.Bytes()}
	if err := config.SaveStatus(paths, st); err != nil {
		return err
	}
	a.logf("secretree configured in the restored repository; `secretree backup` continues the same chain")
	return nil
}
