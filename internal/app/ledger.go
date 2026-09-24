package app

import (
	"encoding/json"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/buildsnap-dev/secretree/internal/crypt"
	"github.com/buildsnap-dev/secretree/internal/gitx"
	"github.com/buildsnap-dev/secretree/internal/vault"
)

// LedgerEntry records one deliberate disclosure: a share link, an export,
// a public mirror. Entries are encrypted to recipients, signed by the
// acting device and hash-chained, like manifests.
type LedgerEntry struct {
	Format     string     `json:"format"`
	Seq        int        `json:"seq"`
	Kind       string     `json:"kind"` // "share", "export", "public-mirror"
	Created    time.Time  `json:"created"`
	Actor      string     `json:"actor"` // signer fingerprint
	ActorName  string     `json:"actor_name,omitempty"`
	Subject    string     `json:"subject"` // what left: "file src/x.go@abc123", "diff a..b"
	Expires    *time.Time `json:"expires,omitempty"`
	Note       string     `json:"note,omitempty"`
	PrevSHA256 *string    `json:"prev_sha256"`
}

const formatLedger = "secretree-ledger/1"

func ledgerDir(repoID string) string { return path.Join(vault.RepoDir(repoID), "ledger") }

// ledgerSeqs lists existing entry numbers.
func ledgerSeqs(r *vault.Reader, repoID string) ([]int, error) {
	dir := ledgerDir(repoID)
	if !r.Exists(dir) {
		return nil, nil
	}
	out, err := gitx.Run(r.Dir, "ls-tree", "--name-only", "HEAD:"+dir)
	if err != nil {
		return nil, err
	}
	var seqs []int
	for _, name := range strings.Split(strings.TrimSpace(out), "\n") {
		if !strings.HasSuffix(name, ".json.age") {
			continue
		}
		n, err := strconv.Atoi(strings.TrimSuffix(name, ".json.age"))
		if err == nil {
			seqs = append(seqs, n)
		}
	}
	sort.Ints(seqs)
	return seqs, nil
}

// loadLedger reads and verifies every entry.
func loadLedger(r *repo, vs *vaultState) ([]LedgerEntry, string, error) {
	seqs, err := ledgerSeqs(vs.Reader, r.Cfg.RepoID)
	if err != nil {
		return nil, "", err
	}
	var entries []LedgerEntry
	var prev *string
	lastHash := ""
	for i, n := range seqs {
		if n != i+1 {
			return nil, "", fmt.Errorf("ledger: entry %06d missing", i+1)
		}
		base := path.Join(ledgerDir(r.Cfg.RepoID), vault.GenName(n)+".json.age")
		cipher, err := vs.Reader.ReadFile(base)
		if err != nil {
			return nil, "", err
		}
		sig, err := vs.Reader.ReadFile(base + ".sig")
		if err != nil {
			return nil, "", err
		}
		if _, err := crypt.Verify(cipher, sig, vs.Signers.ForLedger(n)); err != nil {
			return nil, "", fmt.Errorf("ledger %06d: %w", n, err)
		}
		plain, err := crypt.DecryptBytes(cipher, r.identity)
		if err != nil {
			return nil, "", fmt.Errorf("ledger %06d: %w", n, err)
		}
		var e LedgerEntry
		if err := json.Unmarshal(plain, &e); err != nil {
			return nil, "", fmt.Errorf("ledger %06d: %w", n, err)
		}
		if e.Seq != n || (prev == nil) != (e.PrevSHA256 == nil) || (prev != nil && *prev != *e.PrevSHA256) {
			return nil, "", fmt.Errorf("ledger %06d: chain broken", n)
		}
		entries = append(entries, e)
		lastHash = crypt.SHA256Bytes(cipher)
		prev = &lastHash
	}
	return entries, lastHash, nil
}

// appendLedger writes and pushes one entry.
func (a *App) appendLedger(r *repo, vs *vaultState, e LedgerEntry) error {
	entries, lastHash, err := loadLedger(r, vs)
	if err != nil {
		return err
	}
	e.Format = formatLedger
	e.Seq = len(entries) + 1
	e.Created = time.Now().UTC().Truncate(time.Second)
	if fp, err := r.Keys.Fingerprint(); err == nil {
		e.Actor = fp
	}
	e.ActorName = r.deviceName(vs)
	if lastHash != "" {
		e.PrevSHA256 = &lastHash
	}
	plain, err := json.MarshalIndent(&e, "", "  ")
	if err != nil {
		return err
	}
	cipher, _, err := crypt.EncryptBytes(plain, vs.Recipients)
	if err != nil {
		return err
	}
	sig, err := crypt.Sign(cipher, r.signer)
	if err != nil {
		return err
	}
	dir := ledgerDir(r.Cfg.RepoID)
	if err := os.MkdirAll(filepath.Join(r.Paths.Cache, dir), 0o700); err != nil {
		return err
	}
	name := path.Join(dir, vault.GenName(e.Seq)+".json.age")
	if err := os.WriteFile(filepath.Join(r.Paths.Cache, name), cipher, 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(r.Paths.Cache, name+".sig"), sig, 0o600); err != nil {
		return err
	}
	return commitPush(r.Paths.Cache, vs.Branch, []string{name, name + ".sig"})
}

// Ledger prints the disclosure ledger.
func (a *App) Ledger(dir string) error {
	r, err := a.openRepo(dir)
	if err != nil {
		return err
	}
	vs, err := a.loadVault(r)
	if err != nil {
		return err
	}
	entries, _, err := loadLedger(r, vs)
	if err != nil {
		return err
	}
	if len(entries) == 0 {
		a.logf("no disclosures recorded: nothing has left the vault in plaintext")
		return nil
	}
	a.logf("%d disclosure(s), all signed and chained:", len(entries))
	for _, e := range entries {
		exp := ""
		if e.Expires != nil {
			exp = "  expires " + e.Expires.Format("2006-01-02")
			if time.Now().After(*e.Expires) {
				exp = "  expired " + e.Expires.Format("2006-01-02")
			}
		}
		actor := e.ActorName
		if actor == "" {
			actor = e.Actor
		}
		a.logf("  %06d  %s  %-6s %s  by %s%s%s", e.Seq, e.Created.Format("2006-01-02 15:04"), e.Kind, e.Subject, actor, exp, noteSuffix(e.Note))
	}
	return nil
}

func noteSuffix(n string) string {
	if n == "" {
		return ""
	}
	return "  (" + n + ")"
}

var _ = ssh.FingerprintSHA256

// LedgerAdd records a disclosure made outside secretree (an export to a
// model provider, a dashboard, a public mirror).
func (a *App) LedgerAdd(dir, kind, subject, note string) error {
	if kind == "" || subject == "" {
		return fmt.Errorf("--kind and --subject are required")
	}
	r, err := a.openRepo(dir)
	if err != nil {
		return err
	}
	vs, err := a.loadVault(r)
	if err != nil {
		return err
	}
	if err := a.appendLedger(r, vs, LedgerEntry{Kind: kind, Subject: subject, Note: note}); err != nil {
		return err
	}
	a.logf("ledger: %s %s recorded", kind, subject)
	return nil
}
