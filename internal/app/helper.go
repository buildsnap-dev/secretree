package app

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/buildsnap-dev/secretree/internal/config"
	"github.com/buildsnap-dev/secretree/internal/gitx"
)

// RemoteHelper implements git's remote-helper protocol for
// `secretree::<vault-url>[#<repo-id>]` remotes. git talks to us on
// stdin/stdout; we keep a plaintext mirror in sync with the vault and
// move objects between the user's repository and that mirror.
//
// Protocol: https://git-scm.com/docs/gitremote-helpers
func (a *App) RemoteHelper(remoteName, url string, stdin io.Reader, stdout io.Writer) error {
	gitDir := os.Getenv("GIT_DIR")
	if gitDir == "" {
		return errors.New("GIT_DIR is not set; this command is meant to be run by git")
	}
	if !filepath.IsAbs(gitDir) {
		wd, _ := os.Getwd()
		gitDir = filepath.Join(wd, gitDir)
	}
	h := &helper{app: a, gitDir: gitDir, url: url, out: bufio.NewWriter(stdout)}
	in := bufio.NewScanner(stdin)
	in.Buffer(make([]byte, 1<<20), 1<<20)
	var batch []string
	batchKind := ""
	for in.Scan() {
		line := in.Text()
		switch {
		case line == "capabilities":
			h.reply("fetch", "push", "option", "")
		case strings.HasPrefix(line, "option "):
			f := strings.Fields(line)
			if len(f) >= 3 && (f[1] == "verbosity" || f[1] == "progress") {
				if f[1] == "verbosity" && f[2] != "1" && f[2] != "0" {
					a.Verbose = true
				}
				h.reply("ok")
			} else {
				h.reply("unsupported")
			}
		case line == "list" || line == "list for-push":
			if err := h.list(); err != nil {
				return h.fail(err)
			}
		case strings.HasPrefix(line, "fetch "):
			batchKind = "fetch"
			batch = append(batch, line)
		case strings.HasPrefix(line, "push "):
			batchKind = "push"
			batch = append(batch, line)
		case line == "":
			var err error
			switch batchKind {
			case "fetch":
				err = h.fetch(batch)
			case "push":
				err = h.push(batch)
			}
			batch, batchKind = nil, ""
			if err != nil {
				return h.fail(err)
			}
		default:
			return h.fail(fmt.Errorf("unknown command %q", line))
		}
	}
	return h.out.Flush()
}

type helper struct {
	app    *App
	gitDir string
	url    string
	out    *bufio.Writer
	repo   *repo
	vs     *vaultState
}

func (h *helper) reply(lines ...string) {
	for _, l := range lines {
		h.out.WriteString(l + "\n")
	}
	h.out.Flush()
}

func (h *helper) fail(err error) error {
	h.out.Flush()
	return err
}

// open loads (or auto-initialises) the repository and syncs the mirror.
func (h *helper) open() error {
	if h.repo == nil {
		if _, err := os.Stat(config.NewPaths(h.gitDir).Config); err != nil {
			if err := h.app.autoInit(h.gitDir, h.url); err != nil {
				return err
			}
		}
		r, err := h.app.openRepoGitDir(h.gitDir)
		if err != nil {
			return err
		}
		h.repo = r
	}
	vs, err := h.app.loadVault(h.repo)
	if err != nil {
		return err
	}
	h.vs = vs
	return h.app.mirrorSync(h.repo, vs)
}

func (h *helper) list() error {
	if err := h.open(); err != nil {
		return err
	}
	refs, err := mirrorRefs(h.repo.Paths.Mirror)
	if err != nil {
		return err
	}
	for _, line := range gitx.SortedRefs(refs) {
		f := strings.Fields(line)
		h.out.WriteString(f[1] + " " + f[0] + "\n")
	}
	if head, err := gitx.Run(h.repo.Paths.Mirror, "symbolic-ref", "-q", "HEAD"); err == nil {
		head = strings.TrimSpace(head)
		if _, ok := refs[head]; ok {
			h.out.WriteString("@" + head + " HEAD\n")
		}
	}
	h.reply("")
	return nil
}

func (h *helper) fetch(batch []string) error {
	if h.repo == nil {
		if err := h.open(); err != nil {
			return err
		}
	}
	var shas []string
	for _, l := range batch {
		f := strings.Fields(l)
		if len(f) >= 2 {
			shas = append(shas, f[1])
		}
	}
	if len(shas) > 0 {
		args := append([]string{"--git-dir", h.gitDir, "fetch", "--quiet", "--no-tags", "--no-write-fetch-head", h.repo.Paths.Mirror}, shas...)
		if _, err := gitx.Run(filepath.Dir(h.gitDir), args...); err != nil {
			return fmt.Errorf("fetch from mirror: %w", err)
		}
	}
	h.reply("")
	return nil
}

// push moves refs into the mirror with git's own fast-forward rules, then
// appends one generation to the vault. If the vault rejects it (another
// writer got there first) the mirror is rolled back and every ref is
// reported as an error, so git shows the familiar "fetch first".
func (h *helper) push(batch []string) error {
	if err := h.open(); err != nil {
		return err
	}
	r := h.repo
	unlock, err := r.lock()
	if err != nil {
		return err
	}
	defer unlock()

	type spec struct{ src, dst string }
	var specs []spec
	var refspecs []string
	for _, l := range batch {
		rs := strings.TrimPrefix(l, "push ")
		refspecs = append(refspecs, rs)
		force := strings.HasPrefix(rs, "+")
		src, dst, _ := strings.Cut(strings.TrimPrefix(rs, "+"), ":")
		_ = force
		specs = append(specs, spec{src, dst})
	}
	before, err := gitx.RefMap(r.Paths.Mirror)
	if err != nil {
		return err
	}
	args := append([]string{"--git-dir", h.gitDir, "push", "--porcelain", "--no-verify", r.Paths.Mirror}, refspecs...)
	out, pushErr := gitx.Run(filepath.Dir(h.gitDir), args...)
	if pushErr != nil {
		var ge *gitx.Error
		if errors.As(pushErr, &ge) && ge.Stderr != "" && out == "" {
			return fmt.Errorf("push to mirror: %w", pushErr)
		}
	}
	results := map[string]string{} // dst -> "" (ok) or error text
	for _, line := range strings.Split(out, "\n") {
		if len(line) < 2 || line == "Done" {
			continue
		}
		flag := line[0]
		parts := strings.Split(strings.TrimPrefix(line[1:], "\t"), "\t")
		if len(parts) < 1 || parts[0] == "" {
			continue
		}
		_, dst, _ := strings.Cut(parts[0], ":")
		switch flag {
		case '!':
			msg := "rejected"
			if len(parts) >= 2 {
				msg = parts[1]
				if i := strings.Index(msg, "("); i >= 0 {
					msg = strings.Trim(msg[i:], "()")
				}
			}
			results[dst] = msg
		default:
			results[dst] = ""
		}
	}
	changed := false
	for _, s := range specs {
		if msg, ok := results[s.dst]; ok && msg == "" {
			changed = true
		}
	}
	if changed {
		after, _ := gitx.RefMap(r.Paths.Mirror)
		if err := setMirrorHead(r.Paths.Mirror, headOf(r.Paths.Mirror), after); err != nil {
			return err
		}
		status, err := config.LoadStatus(r.Paths)
		if err != nil {
			return err
		}
		res, err := h.app.writeGeneration(r, h.vs, status, genOptions{Source: r.Paths.Mirror})
		if err != nil {
			_ = gitx.ApplyRefs(r.Paths.Mirror, before)
			msg := "vault error: " + err.Error()
			if errors.Is(err, errPushRejected) {
				msg = "vault rejected (someone pushed first; fetch and retry)"
			}
			for _, s := range specs {
				if results[s.dst] == "" {
					results[s.dst] = msg
				}
			}
		} else if !res.Skipped {
			_ = config.SaveMirrorState(r.Paths, &config.MirrorState{AppliedGeneration: res.Number, AppliedHash: res.ManifestHash})
			h.app.debugf("generation %06d pushed to vault (%s, %s)", res.Number, res.Kind, humanBytes(res.Bytes))
		}
	}
	for _, s := range specs {
		msg, ok := results[s.dst]
		switch {
		case !ok:
			h.out.WriteString("error " + s.dst + " \"no result from git push\"\n")
		case msg == "":
			h.out.WriteString("ok " + s.dst + "\n")
		default:
			h.out.WriteString("error " + s.dst + " \"" + strings.ReplaceAll(msg, "\"", "'") + "\"\n")
		}
	}
	h.reply("")
	return nil
}

func headOf(dir string) string {
	out, err := gitx.Run(dir, "symbolic-ref", "-q", "HEAD")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(out)
}

// ParseHelperURL splits "<vault-url>#<repo-id>".
func ParseHelperURL(url string) (vaultURL, repoID string) {
	if i := strings.LastIndex(url, "#"); i >= 0 {
		return url[:i], url[i+1:]
	}
	return url, ""
}
