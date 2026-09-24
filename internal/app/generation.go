package app

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"filippo.io/age"

	"github.com/buildsnap-dev/secretree/internal/archive"
	"github.com/buildsnap-dev/secretree/internal/config"
	"github.com/buildsnap-dev/secretree/internal/crypt"
	"github.com/buildsnap-dev/secretree/internal/gitx"
	"github.com/buildsnap-dev/secretree/internal/vault"
)

// vaultState is what a synced cache tells us about the vault.
type vaultState struct {
	Branch     string
	Meta       *vault.Meta
	Signers    *vault.SignerSet
	Recipients []age.Recipient
	Chain      *vault.Chain
	Reader     *vault.Reader
}

// loadVault syncs the cache and verifies metadata and chain.
func (a *App) loadVault(r *repo) (*vaultState, error) {
	branch, empty, err := syncCache(r.Cfg.VaultURL, r.Paths.Cache, r.Cfg.VaultBranch)
	if err != nil {
		return nil, err
	}
	if empty {
		return nil, errors.New("vault is empty; run secretree init first")
	}
	fp, _ := r.Keys.Fingerprint()
	reader := &vault.Reader{Dir: r.Paths.Cache, CacheDir: filepath.Join(r.Paths.Root, "manifest-cache", strings.TrimPrefix(fp, "SHA256:"))}
	pub, _ := r.Keys.PublicKey()
	meta, signers, err := vault.LoadMeta(reader, pub)
	if err != nil {
		return nil, err
	}
	if meta.VaultID != r.Cfg.VaultID {
		return nil, fmt.Errorf("remote holds vault %s, config expects %s", meta.VaultID, r.Cfg.VaultID)
	}
	recipients, err := crypt.ParseRecipients(meta.Recipients)
	if err != nil {
		return nil, err
	}
	chain, err := vault.LoadChain(reader, meta.VaultID, r.Cfg.RepoID, r.identity, signers)
	if err != nil {
		return nil, fmt.Errorf("existing chain failed verification, refusing to append: %w", err)
	}
	if err := checkRollback(r, chain); err != nil {
		return nil, err
	}
	vs := &vaultState{Branch: branch, Meta: meta, Signers: signers, Recipients: recipients, Chain: chain, Reader: reader}
	// remember the tip so a later rollback is noticed even by read-only commands
	if last := chain.Last(); last != nil {
		if st, err := config.LoadStatus(r.Paths); err == nil && (last.Num > st.LastGeneration || (last.Num == st.LastGeneration && st.LastManifestHash == "")) {
			st.LastGeneration, st.LastManifestHash = last.Num, last.ManifestCipherHash
			_ = config.SaveStatus(r.Paths, st)
		}
	}
	return vs, nil
}

// ErrRolledBack is returned when the vault on the host no longer contains
// a generation this device knows it wrote or saw: the host (or someone
// with its credentials) removed or replaced history.
var ErrRolledBack = errors.New("vault rolled back")

// checkRollback compares the chain with what this device last recorded.
func checkRollback(r *repo, chain *vault.Chain) error {
	st, err := config.LoadStatus(r.Paths)
	if err != nil || st.LastGeneration == 0 || st.LastManifestHash == "" {
		return nil
	}
	if r.acceptRollback {
		return nil
	}
	g := chain.Get(st.LastGeneration)
	switch {
	case g == nil:
		last := 0
		if chain.Last() != nil {
			last = chain.Last().Num
		}
		return fmt.Errorf("%w: this device recorded generation %06d on the host, the host now ends at %06d. History was deleted or rewritten on the remote. Nothing is lost locally; run `secretree repair` from a device that holds the data to rebuild the chain, or `secretree verify` to inspect", ErrRolledBack, st.LastGeneration, last)
	case g.ManifestCipherHash != st.LastManifestHash:
		return fmt.Errorf("%w: generation %06d on the host is not the one this device recorded (manifest hash differs). Someone replaced history on the remote. Run `secretree verify`, then `secretree repair` from a device that holds the data", ErrRolledBack, st.LastGeneration)
	}
	return nil
}

// loadVaultLocal reads the vault from the existing cache without fetching;
// for cheap UI chrome and offline views.
func (a *App) loadVaultLocal(r *repo) (*vaultState, error) {
	if _, err := os.Stat(filepath.Join(r.Paths.Cache, ".git")); err != nil {
		return nil, errors.New("vault not synced yet")
	}
	fp, _ := r.Keys.Fingerprint()
	reader := &vault.Reader{Dir: r.Paths.Cache, CacheDir: filepath.Join(r.Paths.Root, "manifest-cache", strings.TrimPrefix(fp, "SHA256:"))}
	pub, _ := r.Keys.PublicKey()
	meta, signers, err := vault.LoadMeta(reader, pub)
	if err != nil {
		return nil, err
	}
	recipients, err := crypt.ParseRecipients(meta.Recipients)
	if err != nil {
		return nil, err
	}
	chain, err := vault.LoadChain(reader, meta.VaultID, r.Cfg.RepoID, r.identity, signers)
	if err != nil {
		return nil, err
	}
	return &vaultState{Branch: r.Cfg.VaultBranch, Meta: meta, Signers: signers, Recipients: recipients, Chain: chain, Reader: reader}, nil
}

// genOptions controls writeGeneration.
type genOptions struct {
	Source    string // repository to bundle: the work tree or the mirror
	Full      bool
	WithState bool // include the configured state archive (work-tree backups only)
}

// genResult describes a written generation.
type genResult struct {
	Number       int
	Kind         string
	Refs         map[string]string
	ManifestHash string
	Bytes        int64
	Skipped      bool // nothing to write
}

// writeGeneration appends one generation to the chain and pushes it. The
// host's rejection of a non-fast-forward push (another writer got there
// first) surfaces as errPushRejected.
func (a *App) writeGeneration(r *repo, vs *vaultState, status *config.Status, o genOptions) (*genResult, error) {
	head, err := gitx.Head(o.Source)
	if err != nil {
		return nil, err
	}
	refs, err := gitx.RefMap(o.Source)
	if err != nil {
		return nil, err
	}
	tmp, cleanup, err := r.tmpDir("gen")
	if err != nil {
		return nil, err
	}
	defer cleanup()

	chain := vs.Chain
	last := chain.Last()
	n := 1
	if last != nil {
		n = last.Num + 1
	}
	kind, reason := a.decideKind(r, chain, status, o.Source, o.Full)
	a.debugf("generation %06d: %s (%s)", n, kind, reason)

	var stateFile string
	stateChanged := false
	if o.WithState && (len(r.Cfg.State.Include) > 0 || r.Cfg.State.PreHook != "") {
		stateFile = filepath.Join(tmp, "state.tar.zst")
		ok, err := archive.Build(archive.Spec{
			Root: r.Work, Include: r.Cfg.State.Include, Exclude: r.Cfg.State.Exclude, PreHook: r.Cfg.State.PreHook,
		}, stateFile, filepath.Join(tmp, "stage"))
		if err != nil {
			return nil, err
		}
		if !ok {
			stateFile = ""
		} else {
			h, err := crypt.SHA256File(stateFile)
			if err != nil {
				return nil, err
			}
			stateChanged = last == nil || last.Opaque() || last.Manifest.File(vault.RoleState) == nil || last.Manifest.File(vault.RoleState).PlaintextSHA256 != h
		}
	}

	bundleFile := filepath.Join(tmp, "repo.bundle")
	var prereqs []string
	var base *int
	switch kind {
	case vault.KindFull:
		if err := gitx.BundleCreate(o.Source, bundleFile, nil); err != nil {
			return nil, fmt.Errorf("bundle: %w", err)
		}
	case vault.KindIncremental:
		b := last.Num
		base = &b
		exclude := uniqueCommits(o.Source, last.Manifest.Refs)
		err := gitx.BundleCreate(o.Source, bundleFile, exclude)
		switch {
		case errors.Is(err, gitx.ErrEmptyBundle):
			bundleFile = ""
		case err != nil:
			return nil, fmt.Errorf("bundle: %w", err)
		default:
			if prereqs, err = gitx.BundlePrerequisites(bundleFile); err != nil {
				return nil, err
			}
		}
	}
	refsChanged := last == nil || last.Opaque() || gitx.DiffRefs(last.Manifest.Refs, refs) != "" || last.Manifest.Source.Head != head
	if last != nil && last.Opaque() && kind != vault.KindFull {
		return nil, errors.New("previous generation is unreadable; a full generation is required")
	}
	if kind == vault.KindIncremental && bundleFile == "" && !refsChanged && !stateChanged {
		return &genResult{Number: last.Num, Kind: last.Manifest.Kind, Refs: refs, ManifestHash: last.ManifestCipherHash, Skipped: true}, nil
	}

	repoDir := vault.RepoDir(r.Cfg.RepoID)
	if err := os.MkdirAll(filepath.Join(r.Paths.Cache, repoDir), 0o700); err != nil {
		return nil, err
	}
	var files []vault.FileEntry
	var written []string
	if bundleFile != "" {
		name := vault.BundleName(n)
		d, err := crypt.EncryptFile(filepath.Join(r.Paths.Cache, repoDir, name), bundleFile, vs.Recipients)
		if err != nil {
			return nil, err
		}
		_ = os.Remove(bundleFile)
		files = append(files, vault.FileEntry{Name: name, Role: vault.RoleBundle, ContentEncoding: vault.EncodingNone,
			PlaintextSHA256: d.PlaintextSHA256, CiphertextSHA256: d.CiphertextSHA256, Size: d.Size})
		written = append(written, repoDir+"/"+name)
	}
	if stateFile != "" {
		name := vault.StateName(n)
		d, err := crypt.EncryptFile(filepath.Join(r.Paths.Cache, repoDir, name), stateFile, vs.Recipients)
		if err != nil {
			return nil, err
		}
		_ = os.Remove(stateFile)
		files = append(files, vault.FileEntry{Name: name, Role: vault.RoleState, ContentEncoding: vault.EncodingZstd,
			PlaintextSHA256: d.PlaintextSHA256, CiphertextSHA256: d.CiphertextSHA256, Size: d.Size})
		written = append(written, repoDir+"/"+name)
	}

	m := vault.Manifest{
		Format:        vault.FormatManifest,
		VaultID:       vs.Meta.VaultID,
		RepoID:        r.Cfg.RepoID,
		Generation:    n,
		Kind:          kind,
		Base:          base,
		Created:       time.Now().UTC().Truncate(time.Second),
		Source:        vault.Source{Label: r.Cfg.Label, Head: head},
		Refs:          refs,
		Prerequisites: prereqs,
		Files:         files,
		Tool:          "secretree/" + Version,
	}
	if prereqs == nil {
		m.Prerequisites = []string{}
	}
	if last != nil {
		h := last.ManifestCipherHash
		m.PrevManifestSHA256 = &h
	}
	plain, err := json.MarshalIndent(&m, "", "  ")
	if err != nil {
		return nil, err
	}
	cipher, _, err := crypt.EncryptBytes(plain, vs.Recipients)
	if err != nil {
		return nil, err
	}
	sig, err := crypt.Sign(cipher, r.signer)
	if err != nil {
		return nil, err
	}
	mp := vault.ManifestPath(r.Cfg.RepoID, n)
	if err := os.WriteFile(filepath.Join(r.Paths.Cache, mp), cipher, 0o600); err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(r.Paths.Cache, mp+".sig"), sig, 0o600); err != nil {
		return nil, err
	}
	written = append(written, mp, mp+".sig")

	if err := commitPush(r.Paths.Cache, vs.Branch, written); err != nil {
		return nil, err
	}
	var total int64
	for _, f := range files {
		total += f.Size
	}
	now := time.Now().UTC()
	status.LastGeneration = n
	status.LastManifestHash = crypt.SHA256Bytes(cipher)
	status.LastBackup = &now
	status.Generations = n
	status.ChainBytes = chain.Bytes() + total
	status.LastError = ""
	status.LastErrorTime = nil
	if err := config.SaveStatus(r.Paths, status); err != nil {
		return nil, err
	}
	return &genResult{Number: n, Kind: kind, Refs: refs, ManifestHash: crypt.SHA256Bytes(cipher), Bytes: total}, nil
}

// decideKind picks full vs incremental and explains why.
func (a *App) decideKind(r *repo, chain *vault.Chain, status *config.Status, source string, force bool) (string, string) {
	last := chain.Last()
	if last == nil {
		return vault.KindFull, "first generation"
	}
	if force {
		return vault.KindFull, "--full"
	}
	if status.LastProofGeneration < status.LastGeneration && status.LastError != "" {
		return vault.KindFull, "previous generation was not proven restorable"
	}
	var lastFull *vault.Generation
	incCount := 0
	var incBytes, fullBytes int64
	if last.Opaque() {
		return vault.KindFull, "previous generation is not readable by this key"
	}
	for i := range chain.Gens {
		g := &chain.Gens[i]
		if g.Opaque() {
			continue
		}
		if g.Manifest.Kind == vault.KindFull {
			lastFull, incCount, incBytes = g, 0, 0
			fullBytes = 0
			if f := g.Manifest.File(vault.RoleBundle); f != nil {
				fullBytes = f.Size
			}
			continue
		}
		incCount++
		if f := g.Manifest.File(vault.RoleBundle); f != nil {
			incBytes += f.Size
		}
	}
	if lastFull == nil {
		return vault.KindFull, "no full generation in chain"
	}
	if incCount >= r.Cfg.FullEvery {
		return vault.KindFull, fmt.Sprintf("%d incrementals since last full", incCount)
	}
	if fullBytes > 0 && float64(incBytes) > r.Cfg.FullRatio*float64(fullBytes) {
		return vault.KindFull, "incrementals outgrew the last full"
	}
	for _, id := range last.Manifest.Refs {
		if !gitx.HasObject(source, id) {
			return vault.KindFull, "previous tip " + id[:8] + " no longer exists in the source"
		}
	}
	return vault.KindIncremental, "base " + vault.GenName(last.Num)
}

// uniqueCommits returns the distinct commit/tag ids among ref targets.
func uniqueCommits(work string, refs map[string]string) []string {
	seen := map[string]bool{}
	var out []string
	for _, id := range refs {
		if seen[id] {
			continue
		}
		seen[id] = true
		t, err := gitx.Run(work, "cat-file", "-t", id)
		if err != nil {
			continue
		}
		switch t[:len(t)-1] {
		case "commit", "tag":
			out = append(out, id)
		}
	}
	sort.Strings(out)
	return out
}
