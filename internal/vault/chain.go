package vault

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"filippo.io/age"
	"golang.org/x/crypto/ssh"

	"github.com/buildsnap-dev/secretree/internal/crypt"
	"github.com/buildsnap-dev/secretree/internal/gitx"
	"github.com/buildsnap-dev/secretree/internal/keys"
)

// Reader reads files out of a git clone of the vault at HEAD. The clone may
// be a partial (--filter=blob:none --no-checkout) clone: blobs are fetched
// on demand, which is what makes the restore proof cheap on big vaults.
//
// CacheDir, when set, stores verified and decrypted manifests keyed by
// their blob id, so loading a long chain costs one git call instead of two
// per generation. Entries are written only after signature verification
// and are private to this key (0600); a different key must use a
// different cache directory.
type Reader struct {
	Dir      string
	CacheDir string
}

// blobIDs maps vault-relative paths under dir to blob ids, in one git call.
func (r *Reader) blobIDs(dir string) (map[string]string, error) {
	if !r.Exists(dir) {
		return nil, nil
	}
	out, err := gitx.Run(r.Dir, "ls-tree", "HEAD:"+dir)
	if err != nil {
		return nil, err
	}
	m := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		// <mode> <type> <oid>\t<name>
		meta, name, ok := strings.Cut(line, "\t")
		if !ok {
			continue
		}
		f := strings.Fields(meta)
		if len(f) == 3 && f[1] == "blob" {
			m[name] = f[2]
		}
	}
	return m, nil
}

type cachedManifest struct {
	CipherSHA256 string   `json:"cipher_sha256"`
	Manifest     Manifest `json:"manifest"`
	Opaque       bool     `json:"opaque"`
}

func (r *Reader) cacheGet(oid string) (*cachedManifest, bool) {
	if r.CacheDir == "" {
		return nil, false
	}
	data, err := os.ReadFile(filepath.Join(r.CacheDir, oid+".json"))
	if err != nil {
		return nil, false
	}
	var c cachedManifest
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, false
	}
	return &c, true
}

func (r *Reader) cachePut(oid string, c *cachedManifest) {
	if r.CacheDir == "" {
		return
	}
	if err := os.MkdirAll(r.CacheDir, 0o700); err != nil {
		return
	}
	data, err := json.Marshal(c)
	if err != nil {
		return
	}
	tmp := filepath.Join(r.CacheDir, oid+".tmp")
	if err := os.WriteFile(tmp, data, 0o600); err == nil {
		_ = os.Rename(tmp, filepath.Join(r.CacheDir, oid+".json"))
	}
}

// ReadFile returns a small file's bytes.
func (r *Reader) ReadFile(rel string) ([]byte, error) {
	out, err := gitx.Run(r.Dir, "cat-file", "blob", "HEAD:"+rel)
	if err != nil {
		return nil, fmt.Errorf("vault: read %s: %w", rel, err)
	}
	return []byte(out), nil
}

// ExtractFile streams a file to disk.
func (r *Reader) ExtractFile(rel, dst string) error {
	if err := gitx.RunToFile(r.Dir, dst, "cat-file", "blob", "HEAD:"+rel); err != nil {
		return fmt.Errorf("vault: extract %s: %w", rel, err)
	}
	return nil
}

// Exists reports whether a path is in the vault tree.
func (r *Reader) Exists(rel string) bool {
	_, err := gitx.Run(r.Dir, "cat-file", "-e", "HEAD:"+rel)
	return err == nil
}

// Empty reports whether the vault has no commits yet.
func (r *Reader) Empty() bool {
	_, err := gitx.Run(r.Dir, "rev-parse", "--verify", "-q", "HEAD")
	return err != nil
}

// ListRepos lists repo ids present in the vault.
func (r *Reader) ListRepos() ([]string, error) {
	if !r.Exists(ReposDir) {
		return nil, nil
	}
	out, err := gitx.Run(r.Dir, "ls-tree", "--name-only", "HEAD:"+ReposDir)
	if err != nil {
		return nil, err
	}
	var ids []string
	for _, l := range strings.Split(strings.TrimSpace(out), "\n") {
		if l != "" {
			ids = append(ids, l)
		}
	}
	sort.Strings(ids)
	return ids, nil
}

// Generations lists the generation numbers stored for a repo, ascending.
func (r *Reader) Generations(repoID string) ([]int, error) {
	if !r.Exists(RepoDir(repoID)) {
		return nil, nil
	}
	out, err := gitx.Run(r.Dir, "ls-tree", "--name-only", "HEAD:"+RepoDir(repoID))
	if err != nil {
		return nil, err
	}
	var gens []int
	for _, name := range strings.Split(strings.TrimSpace(out), "\n") {
		if !strings.HasSuffix(name, ".manifest.age") {
			continue
		}
		n, err := strconv.Atoi(strings.TrimSuffix(name, ".manifest.age"))
		if err != nil {
			return nil, fmt.Errorf("vault: unexpected file %s", name)
		}
		gens = append(gens, n)
	}
	sort.Ints(gens)
	return gens, nil
}

// SignerSet is the roster: active signers plus revoked ones with their
// cut-off points.
type SignerSet struct {
	Active  []ssh.PublicKey
	Revoked []revoked
}

type revoked struct {
	Key            ssh.PublicKey
	RevokedAt      time.Time
	LastGeneration int
	LastLedger     int
}

// At returns the keys that were allowed to sign at time t (for
// collaboration events, which carry their own timestamps).
func (s *SignerSet) At(t time.Time) []ssh.PublicKey {
	out := append([]ssh.PublicKey{}, s.Active...)
	for _, r := range s.Revoked {
		if !t.After(r.RevokedAt) {
			out = append(out, r.Key)
		}
	}
	return out
}

// ForGeneration returns the keys allowed to have signed generation n.
func (s *SignerSet) ForGeneration(n int) []ssh.PublicKey {
	out := append([]ssh.PublicKey{}, s.Active...)
	for _, r := range s.Revoked {
		if n <= r.LastGeneration {
			out = append(out, r.Key)
		}
	}
	return out
}

// ForLedger returns the keys allowed to have signed ledger entry n.
func (s *SignerSet) ForLedger(n int) []ssh.PublicKey {
	out := append([]ssh.PublicKey{}, s.Active...)
	for _, r := range s.Revoked {
		if n <= r.LastLedger {
			out = append(out, r.Key)
		}
	}
	return out
}

// LoadMeta reads and verifies vault.json. trusted must be one of the active
// signers: it is the fingerprint the recovery kit vouches for, and it is what
// turns a self-signed roster into something worth believing.
func LoadMeta(r *Reader, trusted ssh.PublicKey) (*Meta, *SignerSet, error) {
	data, err := r.ReadFile(MetaFile)
	if err != nil {
		return nil, nil, err
	}
	sig, err := r.ReadFile(MetaFile + ".sig")
	if err != nil {
		return nil, nil, err
	}
	var m Meta
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, nil, fmt.Errorf("vault.json: %w", err)
	}
	if !strings.HasPrefix(m.Format, "secretree-vault/1") {
		return nil, nil, fmt.Errorf("vault.json: unsupported format %q", m.Format)
	}
	signers, err := keys.ParseAllowedSigners(m.AllowedSigners)
	if err != nil {
		return nil, nil, fmt.Errorf("vault.json: %w", err)
	}
	found := false
	for _, s := range signers {
		if string(s.Marshal()) == string(trusted.Marshal()) {
			found = true
		}
	}
	if !found {
		return nil, nil, fmt.Errorf("vault.json: our signing key %s is not an allowed signer of this vault", ssh.FingerprintSHA256(trusted))
	}
	if _, err := crypt.Verify(data, sig, signers); err != nil {
		return nil, nil, fmt.Errorf("vault.json: %w", err)
	}
	set := &SignerSet{Active: signers}
	for _, rv := range m.RevokedSigners {
		pubs, err := keys.ParseAllowedSigners([]string{rv.Line})
		if err != nil {
			return nil, nil, fmt.Errorf("vault.json: revoked signer: %w", err)
		}
		set.Revoked = append(set.Revoked, revoked{Key: pubs[0], RevokedAt: rv.RevokedAt, LastGeneration: rv.LastGeneration, LastLedger: rv.LastLedger})
	}
	return &m, set, nil
}

// Generation is one verified manifest. Manifest is nil for an "opaque"
// generation: its signature and place in the hash chain are verified, but
// it was encrypted to recipients that do not include this key (it predates
// this member). Such generations cannot be restored by this key, and the
// chain guarantees nobody replaced them.
type Generation struct {
	Num                int
	Manifest           *Manifest
	ManifestCipherHash string
}

// Opaque reports whether the generation is unreadable by this key.
func (g *Generation) Opaque() bool { return g.Manifest == nil }

// Chain is the verified sequence of generations of one repo.
type Chain struct {
	RepoID string
	Gens   []Generation
}

// Last returns the newest generation or nil.
func (c *Chain) Last() *Generation {
	if len(c.Gens) == 0 {
		return nil
	}
	return &c.Gens[len(c.Gens)-1]
}

// Readable counts generations this key can decrypt.
func (c *Chain) Readable() int {
	n := 0
	for i := range c.Gens {
		if !c.Gens[i].Opaque() {
			n++
		}
	}
	return n
}

// Get returns generation n or nil.
func (c *Chain) Get(n int) *Generation {
	for i := range c.Gens {
		if c.Gens[i].Num == n {
			return &c.Gens[i]
		}
	}
	return nil
}

// Bytes is the total ciphertext size of the chain.
func (c *Chain) Bytes() int64 {
	var n int64
	for _, g := range c.Gens {
		if g.Opaque() {
			continue
		}
		for _, f := range g.Manifest.Files {
			n += f.Size
		}
	}
	return n
}

// LoadChain reads every generation of a repo, verifying signature, hash
// chain and manifest contents. Any gap or mismatch is an error: the chain is
// either whole or it is not.
func LoadChain(r *Reader, vaultID, repoID string, identity age.Identity, signers *SignerSet) (*Chain, error) {
	nums, err := r.Generations(repoID)
	if err != nil {
		return nil, err
	}
	oids, err := r.blobIDs(RepoDir(repoID))
	if err != nil {
		return nil, err
	}
	chain := &Chain{RepoID: repoID}
	var prevHash *string
	for i, n := range nums {
		if n != i+1 {
			return nil, fmt.Errorf("chain %s: generation %06d missing (found %06d)", repoID, i+1, n)
		}
		name := GenName(n) + ".manifest.age"
		oid := oids[name]
		if c, ok := r.cacheGet(oid); ok && oid != "" {
			// already verified and decrypted by this key; only the chain link is re-checked
			if err := checkLink(n, prevHash, c.CipherSHA256, c.Opaque, &c.Manifest); err != nil {
				return nil, err
			}
			h := c.CipherSHA256
			g := Generation{Num: n, ManifestCipherHash: h}
			if !c.Opaque {
				m := c.Manifest
				g.Manifest = &m
			}
			chain.Gens = append(chain.Gens, g)
			prevHash = &h
			continue
		}
		cipher, err := r.ReadFile(ManifestPath(repoID, n))
		if err != nil {
			return nil, err
		}
		sig, err := r.ReadFile(SigPath(repoID, n))
		if err != nil {
			return nil, err
		}
		if _, err := crypt.Verify(cipher, sig, signers.ForGeneration(n)); err != nil {
			return nil, fmt.Errorf("generation %06d: %w", n, err)
		}
		h := crypt.SHA256Bytes(cipher)
		plain, err := crypt.DecryptBytes(cipher, identity)
		if err != nil {
			var noMatch *age.NoIdentityMatchError
			if errors.As(err, &noMatch) {
				// encrypted before this key was a recipient: opaque but verified
				if err := checkLink(n, prevHash, h, true, nil); err != nil {
					return nil, err
				}
				chain.Gens = append(chain.Gens, Generation{Num: n, ManifestCipherHash: h})
				r.cachePut(oid, &cachedManifest{CipherSHA256: h, Opaque: true})
				prevHash = &h
				continue
			}
			return nil, fmt.Errorf("generation %06d manifest: %w", n, err)
		}
		var m Manifest
		if err := json.Unmarshal(plain, &m); err != nil {
			return nil, fmt.Errorf("generation %06d manifest: %w", n, err)
		}
		if err := checkManifest(&m, vaultID, repoID, n, prevHash); err != nil {
			return nil, err
		}
		chain.Gens = append(chain.Gens, Generation{Num: n, Manifest: &m, ManifestCipherHash: h})
		r.cachePut(oid, &cachedManifest{CipherSHA256: h, Manifest: m})
		prevHash = &h
	}
	return chain, nil
}

// checkLink verifies the hash chain for a cached or opaque generation.
func checkLink(n int, prevHash *string, _ string, opaque bool, m *Manifest) error {
	if opaque || m == nil {
		return nil // an opaque manifest's own link is checked by its successor
	}
	switch {
	case prevHash == nil && m.PrevManifestSHA256 != nil:
		return fmt.Errorf("generation %06d: first manifest must not link to a predecessor", n)
	case prevHash != nil && (m.PrevManifestSHA256 == nil || *m.PrevManifestSHA256 != *prevHash):
		return fmt.Errorf("generation %06d: hash chain broken (a generation was altered or replaced)", n)
	}
	return nil
}

func checkManifest(m *Manifest, vaultID, repoID string, n int, prevHash *string) error {
	if !strings.HasPrefix(m.Format, "secretree-manifest/1") {
		return fmt.Errorf("generation %06d: unsupported manifest format %q", n, m.Format)
	}
	if m.VaultID != vaultID || m.RepoID != repoID || m.Generation != n {
		return fmt.Errorf("generation %06d: manifest identity mismatch (vault %s repo %s gen %d)", n, m.VaultID, m.RepoID, m.Generation)
	}
	switch m.Kind {
	case KindFull:
		if m.Base != nil || len(m.Prerequisites) != 0 || m.File(RoleBundle) == nil {
			return fmt.Errorf("generation %06d: malformed full manifest", n)
		}
	case KindIncremental:
		if m.Base == nil || *m.Base != n-1 {
			return fmt.Errorf("generation %06d: incremental must base on %06d", n, n-1)
		}
	default:
		return fmt.Errorf("generation %06d: unknown kind %q", n, m.Kind)
	}
	switch {
	case prevHash == nil && m.PrevManifestSHA256 != nil:
		return fmt.Errorf("generation %06d: first manifest must not link to a predecessor", n)
	case prevHash != nil && (m.PrevManifestSHA256 == nil || *m.PrevManifestSHA256 != *prevHash):
		return fmt.Errorf("generation %06d: hash chain broken (a generation was altered or replaced)", n)
	}
	for _, f := range m.Files {
		if !strings.HasPrefix(f.Name, GenName(n)+".") || strings.Contains(f.Name, "/") {
			return fmt.Errorf("generation %06d: file %q does not belong to it", n, f.Name)
		}
	}
	return nil
}

// RestorePlan lists the generations needed to rebuild target: the nearest
// full at or before it, then every generation up to target.
func (c *Chain) RestorePlan(target int) ([]Generation, error) {
	if target <= 0 && c.Last() != nil {
		target = c.Last().Num
	}
	if c.Get(target) == nil {
		return nil, fmt.Errorf("generation %06d does not exist", target)
	}
	if c.Get(target).Opaque() {
		return nil, fmt.Errorf("generation %06d predates this key's membership and cannot be read by it", target)
	}
	start := -1
	for i := range c.Gens {
		if c.Gens[i].Num <= target && !c.Gens[i].Opaque() && c.Gens[i].Manifest.Kind == KindFull {
			start = i
		}
	}
	if start < 0 {
		return nil, errors.New("no full generation readable by this key before the target")
	}
	var plan []Generation
	for _, g := range c.Gens[start:] {
		if g.Num > target {
			break
		}
		if g.Opaque() {
			return nil, fmt.Errorf("generation %06d is not readable by this key", g.Num)
		}
		plan = append(plan, g)
	}
	return plan, nil
}
