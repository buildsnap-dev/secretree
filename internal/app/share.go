package app

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"filippo.io/age"
	"filippo.io/age/armor"

	"github.com/buildsnap-dev/secretree/internal/config"
	"github.com/buildsnap-dev/secretree/internal/gitx"
	"github.com/buildsnap-dev/secretree/internal/share"
)

// ShareOptions configures Share.
type ShareOptions struct {
	Dir      string
	Path     string // file to share (at Ref)
	Ref      string // default HEAD
	Diff     string // "a..b" or a commit; shares a diff instead of a file
	Expires  time.Duration
	Note     string
	Out      string // HTML file to write
	NoLedger bool
}

// snapshot is what the viewer decrypts.
type snapshot struct {
	Type    string     `json:"type"` // file | diff
	Title   string     `json:"title"`
	Subject string     `json:"subject"`
	Ref     string     `json:"ref"`
	Commit  string     `json:"commit"`
	Created time.Time  `json:"created"`
	Expires *time.Time `json:"expires,omitempty"`
	Note    string     `json:"note,omitempty"`
	Content string     `json:"content"`
}

// Share produces a self-contained HTML page holding an age-encrypted
// snapshot (a file at a ref, or a diff) under a fresh one-off key. The page
// is safe to host anywhere: it is ciphertext plus a static viewer. The key
// travels separately, in the link fragment or by another channel. The
// disclosure is recorded in the ledger.
func (a *App) Share(o ShareOptions) error {
	if o.Path == "" && o.Diff == "" {
		return errors.New("give a path to share, or --diff <a..b>")
	}
	r, err := a.openRepo(o.Dir)
	if err != nil {
		return err
	}
	src := r.Work
	if ms, err := config.LoadMirrorState(r.Paths); err == nil && ms.AppliedGeneration > 0 && o.Diff == "" {
		if _, err := gitx.Run(r.Paths.Mirror, "rev-parse", "--verify", "-q", o.Ref); err == nil {
			src = r.Paths.Mirror
		}
	}
	if o.Ref == "" {
		o.Ref = "HEAD"
	}
	commit, err := gitx.Run(src, "rev-parse", "--verify", o.Ref+"^{commit}")
	if err != nil {
		return fmt.Errorf("ref %s: %w", o.Ref, err)
	}
	commit = strings.TrimSpace(commit)
	s := snapshot{Ref: o.Ref, Commit: commit, Created: time.Now().UTC().Truncate(time.Second), Note: o.Note}
	if o.Expires > 0 {
		t := s.Created.Add(o.Expires)
		s.Expires = &t
	}
	if o.Diff != "" {
		s.Type = "diff"
		var out string
		if strings.Contains(o.Diff, "..") {
			out, err = gitx.Run(src, "diff", o.Diff, "--")
		} else {
			out, err = gitx.Run(src, "show", "--format=commit %H%nAuthor: %an%nDate:   %ad%n%n    %s%n", o.Diff, "--")
		}
		if err != nil {
			return err
		}
		s.Content, s.Subject, s.Title = out, "diff "+o.Diff, r.Cfg.Label+": diff "+o.Diff
	} else {
		rel, err := absRel(r.Work, o.Path)
		if err != nil {
			// not on disk (or outside the tree): treat it as a repository path
			rel = filepath.ToSlash(filepath.Clean(o.Path))
		}
		out, err := gitx.Run(src, "show", commit+":"+rel)
		if err != nil {
			return fmt.Errorf("%s at %s: %w", rel, o.Ref, err)
		}
		if strings.IndexByte(out, 0) >= 0 {
			return errors.New("binary files cannot be shared as text (yet)")
		}
		s.Type, s.Content = "file", out
		s.Subject = fmt.Sprintf("file %s@%s", rel, commit[:8])
		s.Title = r.Cfg.Label + ": " + rel
	}
	plain, err := json.Marshal(&s)
	if err != nil {
		return err
	}
	id, err := age.GenerateX25519Identity()
	if err != nil {
		return err
	}
	var buf bytes.Buffer
	aw := armor.NewWriter(&buf)
	ew, err := age.Encrypt(aw, id.Recipient())
	if err != nil {
		return err
	}
	if _, err := ew.Write(plain); err != nil {
		return err
	}
	if err := ew.Close(); err != nil {
		return err
	}
	if err := aw.Close(); err != nil {
		return err
	}
	html := strings.Replace(share.Viewer, "{{CIPHERTEXT}}", buf.String(), 1)
	out := o.Out
	if out == "" {
		base := "share"
		if s.Type == "file" {
			base = strings.ReplaceAll(filepath.Base(o.Path), ".", "-")
		}
		out = fmt.Sprintf("%s-%s.html", base, commit[:8])
	}
	if err := os.WriteFile(out, []byte(html), 0o644); err != nil {
		return err
	}
	abs, _ := filepath.Abs(out)
	if !o.NoLedger {
		vs, err := a.loadVault(r)
		if err != nil {
			return err
		}
		if err := a.appendLedger(r, vs, LedgerEntry{Kind: "share", Subject: s.Subject, Expires: s.Expires, Note: o.Note}); err != nil {
			return fmt.Errorf("share written but not recorded in the ledger: %w", err)
		}
	}
	a.logf("encrypted share written: %s (%s)", abs, humanBytes(int64(len(html))))
	a.logf("host that file anywhere; it is ciphertext. Send the key through a different channel:")
	a.logf("  key:  %s", id.String())
	a.logf("  link: file://%s#%s", abs, id.String())
	if s.Expires != nil {
		a.logf("  expires %s (advisory: the viewer warns, the ledger records it)", s.Expires.Format(time.RFC3339))
	}
	if !o.NoLedger {
		a.logf("recorded in the disclosure ledger (secretree ledger)")
	}
	return nil
}
