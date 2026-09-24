package app

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/buildsnap-dev/secretree/internal/collab"
	"github.com/buildsnap-dev/secretree/internal/crypt"
	"github.com/buildsnap-dev/secretree/internal/gitx"
)

// secretreeRemote returns the name of the remote that points at a vault
// through the helper, or "" (backup-only repositories).
func secretreeRemote(work string) string {
	out, err := gitx.Run(work, "remote")
	if err != nil {
		return ""
	}
	for _, name := range strings.Fields(out) {
		url, err := gitx.Run(work, "remote", "get-url", name)
		if err == nil && strings.HasPrefix(strings.TrimSpace(url), "secretree::") {
			return name
		}
	}
	return ""
}

// memberNames maps signer fingerprints to member names.
func memberNames(vs *vaultState) map[string]string {
	names := map[string]string{}
	for _, m := range vs.Meta.Members {
		if m.SignerFingerprint != "" {
			names[m.SignerFingerprint] = m.Name
		}
	}
	return names
}

// nameEvents fills ActorName from the roster; events written before a
// device had a member entry keep whatever name they carry.
func nameEvents(vs *vaultState, events []collab.Event) {
	names := memberNames(vs)
	for i := range events {
		if n := names[events[i].Actor]; n != "" {
			events[i].ActorName = n
		}
	}
}

// deviceName is this device's member name, or the repository label when
// it has no roster entry (vaults created before names were recorded).
func (r *repo) deviceName(vs *vaultState) string {
	fp, _ := r.Keys.Fingerprint()
	if n := memberNames(vs)[fp]; n != "" {
		return n
	}
	return r.Cfg.Label
}

// collabStore wires the collab ref to this device's signing key and the
// vault's signer roster.
func (a *App) collabStore(r *repo, vs *vaultState) *collab.Store {
	return &collab.Store{
		Dir:  r.Work,
		Sign: func(data []byte) ([]byte, error) { return crypt.Sign(data, r.signer) },
		Ver: func(data, sig []byte, at time.Time) (string, error) {
			pub, err := crypt.Verify(data, sig, vs.Signers.At(at))
			if err != nil {
				return "", err
			}
			return ssh.FingerprintSHA256(pub), nil
		},
	}
}

// prContext opens everything a PR command needs and syncs collab state.
type prContext struct {
	r       *repo
	vs      *vaultState
	store   *collab.Store
	remote  string
	events  []collab.Event
	prs     []collab.PullRequest
	agents  map[string]bool // signer fingerprints of agent members
	isAgent bool            // this device is an agent
}

func (c *prContext) approvals(pr *collab.PullRequest, head string) ([]string, []string) {
	return pr.Approvals(head, c.agents)
}

func (a *App) openPR(dir string) (*prContext, error) {
	r, err := a.openRepo(dir)
	if err != nil {
		return nil, err
	}
	vs, err := a.loadVault(r)
	if err != nil {
		return nil, err
	}
	c := &prContext{r: r, vs: vs, store: a.collabStore(r, vs), remote: secretreeRemote(r.Work), agents: map[string]bool{}}
	ourFP, _ := r.Keys.Fingerprint()
	for _, m := range vs.Meta.Members {
		if m.Role == "agent" && m.SignerFingerprint != "" {
			c.agents[m.SignerFingerprint] = true
			if m.SignerFingerprint == ourFP {
				c.isAgent = true
			}
		}
	}
	if c.remote != "" {
		if _, err := gitx.Run(r.Work, "fetch", "--quiet", c.remote); err != nil {
			return nil, fmt.Errorf("fetch %s: %w", c.remote, err)
		}
	}
	removed, err := c.store.Sync(c.remote)
	if err != nil {
		return nil, err
	}
	a.reportRemovals(removed)
	return c, c.reload(a)
}

func (c *prContext) reload(a *App) error {
	events, bad, err := c.store.Events()
	if err != nil {
		return err
	}
	for _, b := range bad {
		a.debugf("collab: ignoring %s", b)
	}
	nameEvents(c.vs, events)
	c.events = events
	c.prs = collab.Fold(events)
	return nil
}

// headSHA resolves the current tip of a PR's head branch.
func (c *prContext) headSHA(pr *collab.PullRequest) string {
	for _, ref := range []string{"refs/remotes/" + c.remote + "/" + pr.Head, "refs/heads/" + pr.Head} {
		if c.remote == "" && strings.HasPrefix(ref, "refs/remotes//") {
			continue
		}
		if out, err := gitx.Run(c.r.Work, "rev-parse", "--verify", "-q", ref); err == nil {
			return strings.TrimSpace(out)
		}
	}
	return pr.HeadSHA
}

func (c *prContext) baseSHA(pr *collab.PullRequest) string {
	for _, ref := range []string{"refs/remotes/" + c.remote + "/" + pr.Base, "refs/heads/" + pr.Base} {
		if c.remote == "" && strings.HasPrefix(ref, "refs/remotes//") {
			continue
		}
		if out, err := gitx.Run(c.r.Work, "rev-parse", "--verify", "-q", ref); err == nil {
			return strings.TrimSpace(out)
		}
	}
	return ""
}

func (c *prContext) append(e *collab.Event) error {
	e.ActorName = c.r.deviceName(c.vs)
	if err := c.store.Append(e); err != nil {
		return err
	}
	_, err := c.store.Sync(c.remote)
	return err
}

// PROpenOptions configures PROpen.
type PROpenOptions struct {
	Dir, Title, Body, Base, Head string
}

// PROpen opens a pull request from head onto base.
func (a *App) PROpen(o PROpenOptions) error {
	if o.Title == "" {
		return errors.New("--title is required")
	}
	c, err := a.openPR(o.Dir)
	if err != nil {
		return err
	}
	if o.Head == "" {
		out, err := gitx.Run(c.r.Work, "symbolic-ref", "--short", "-q", "HEAD")
		if err != nil {
			return errors.New("--head is required when HEAD is detached")
		}
		o.Head = strings.TrimSpace(out)
	}
	if o.Base == "" {
		o.Base = "main"
		if _, err := gitx.Run(c.r.Work, "rev-parse", "--verify", "-q", "refs/heads/main"); err != nil {
			o.Base = "master"
		}
	}
	if o.Head == o.Base {
		return fmt.Errorf("head and base are both %s", o.Head)
	}
	if c.remote != "" {
		local, lerr := gitx.Run(c.r.Work, "rev-parse", "--verify", "-q", "refs/heads/"+o.Head)
		tracked, terr := gitx.Run(c.r.Work, "rev-parse", "--verify", "-q", "refs/remotes/"+c.remote+"/"+o.Head)
		if lerr == nil && (terr != nil || strings.TrimSpace(local) != strings.TrimSpace(tracked)) {
			a.logf("pushing %s to %s…", o.Head, c.remote)
			if err := a.pushBranch(c.r.Work, c.remote, o.Head); err != nil {
				return err
			}
		} else if lerr != nil && terr != nil {
			return fmt.Errorf("branch %s exists neither locally nor on the vault", o.Head)
		}
	}
	num := collab.NextNumber(c.prs)
	pr := &collab.PullRequest{Head: o.Head, Base: o.Base}
	head := c.headSHA(pr)
	e := &collab.Event{Kind: collab.KindPR, PR: collab.NewPRID(num), Number: num, Title: o.Title, Body: o.Body, Base: o.Base, Head: o.Head, HeadSHA: head}
	if err := c.append(e); err != nil {
		return err
	}
	a.logf("pull request #%d opened: %s (%s → %s, %s)", num, o.Title, o.Head, o.Base, short(head))
	return nil
}

func short(sha string) string {
	if len(sha) > 8 {
		return sha[:8]
	}
	return sha
}

// PRList prints open (or all) pull requests.
func (a *App) PRList(dir string, all bool) error {
	c, err := a.openPR(dir)
	if err != nil {
		return err
	}
	n := 0
	for i := range c.prs {
		pr := &c.prs[i]
		if !all && pr.State != collab.StateOpen {
			continue
		}
		n++
		head := c.headSHA(pr)
		approved, changes := c.approvals(pr, head)
		checks := collab.Checks(c.events, head)
		a.logf("#%-4d %-7s %-40s %s → %s  by %s  %s%s", pr.Number, pr.State, truncate(pr.Title, 40), pr.Head, pr.Base, pr.Author, reviewSummary(approved, changes), checkSummary(checks))
	}
	if n == 0 {
		a.logf("no open pull requests")
	}
	return nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

func reviewSummary(approved, changes []string) string {
	var parts []string
	if len(approved) > 0 {
		parts = append(parts, fmt.Sprintf("✓%d", len(approved)))
	}
	if len(changes) > 0 {
		parts = append(parts, fmt.Sprintf("✗%d", len(changes)))
	}
	return strings.Join(parts, " ")
}

func checkSummary(checks map[string]collab.Event) string {
	if len(checks) == 0 {
		return ""
	}
	var parts []string
	for name, e := range checks {
		sym := "…"
		switch e.Status {
		case collab.StatusSuccess:
			sym = "✓"
		case collab.StatusFailure:
			sym = "✗"
		}
		parts = append(parts, sym+name)
	}
	return " [" + strings.Join(parts, " ") + "]"
}

// PRShow prints one pull request with its events.
func (a *App) PRShow(dir, ref string) error {
	c, err := a.openPR(dir)
	if err != nil {
		return err
	}
	pr, err := collab.Resolve(c.prs, ref)
	if err != nil {
		return err
	}
	head, base := c.headSHA(pr), c.baseSHA(pr)
	a.logf("#%d %s  [%s]\n%s → %s (%s → %s)  by %s on %s", pr.Number, pr.Title, pr.State, pr.Head, pr.Base, short(head), short(base), pr.Author, pr.Created.Format("2006-01-02 15:04"))
	if pr.Body != "" {
		a.logf("\n%s", pr.Body)
	}
	pol := collab.LoadPolicy(c.r.Work, base)
	approved, changes := c.approvals(pr, head)
	a.logf("\napprovals: %d/%d %v  changes requested: %v", len(approved), pol.RequiredApprovals, approved, changes)
	checks := collab.Checks(c.events, head)
	for name, e := range checks {
		a.logf("check %s: %s  %s", name, e.Status, e.Summary)
	}
	for _, req := range pol.RequiredChecks {
		if _, ok := checks[req]; !ok {
			a.logf("check %s: missing (required)", req)
		}
	}
	a.logf("")
	resolved := pr.Resolved()
	for _, e := range pr.Events {
		who := e.ActorName
		if who == "" {
			who = e.Actor
		}
		when := e.Created.Format("01-02 15:04")
		switch e.Kind {
		case collab.KindComment:
			loc := ""
			if e.Path != "" {
				loc = fmt.Sprintf(" on %s:%d@%s", e.Path, e.Line, short(e.Commit))
				if e.Commit != "" && e.Commit != head {
					if nl, ok := remapLine(c.r.Work, e.Commit, head, e.Path, e.Line); ok {
						loc += fmt.Sprintf(" (now line %d)", nl)
					} else {
						loc += " (outdated)"
					}
				}
			}
			tag := ""
			if c.agents[e.Actor] {
				tag = " [agent]"
			}
			if by, ok := resolved[e.ID]; ok {
				tag += " [resolved by " + by + "]"
			}
			a.logf("[%s] %s%s commented%s (id %s):\n    %s", when, who, tag, loc, e.ID, strings.ReplaceAll(e.Body, "\n", "\n    "))
		case collab.KindReview:
			a.logf("[%s] %s: %s @%s %s", when, who, e.Verdict, short(e.Commit), e.Body)
		case collab.KindState:
			a.logf("[%s] %s marked it %s %s", when, who, e.State, short(e.MergeCommit))
		}
	}
	if pr.State == collab.StateOpen {
		if out, err := gitx.Run(c.r.Work, "diff", "--stat", base+"..."+head); err == nil && strings.TrimSpace(out) != "" {
			a.logf("\n%s", strings.TrimRight(out, "\n"))
		}
	}
	return nil
}

// PRComment adds a comment, optionally anchored to a path and line at the
// current head.
func (a *App) PRComment(dir, ref, body, path string, line int) error {
	if body == "" {
		return errors.New("-m <text> is required")
	}
	c, err := a.openPR(dir)
	if err != nil {
		return err
	}
	pr, err := collab.Resolve(c.prs, ref)
	if err != nil {
		return err
	}
	e := &collab.Event{Kind: collab.KindComment, PR: pr.ID, Body: body, Path: path, Line: line}
	if path != "" {
		e.Commit = c.headSHA(pr)
	}
	if err := c.append(e); err != nil {
		return err
	}
	a.logf("comment added to #%d", pr.Number)
	return nil
}

// PRReview records approve / request_changes / comment for the current head.
func (a *App) PRReview(dir, ref, verdict, body string) error {
	switch verdict {
	case collab.VerdictApprove, collab.VerdictRequestChanges, collab.VerdictComment:
	default:
		return fmt.Errorf("verdict must be approve, request_changes or comment")
	}
	c, err := a.openPR(dir)
	if err != nil {
		return err
	}
	pr, err := collab.Resolve(c.prs, ref)
	if err != nil {
		return err
	}
	if pr.State != collab.StateOpen {
		return fmt.Errorf("#%d is %s", pr.Number, pr.State)
	}
	head := c.headSHA(pr)
	if err := c.append(&collab.Event{Kind: collab.KindReview, PR: pr.ID, Verdict: verdict, Body: body, Commit: head}); err != nil {
		return err
	}
	a.logf("#%d: %s recorded for %s", pr.Number, verdict, short(head))
	return nil
}

// PRResolve marks a comment's thread resolved.
func (a *App) PRResolve(dir, ref, commentID string) error {
	c, err := a.openPR(dir)
	if err != nil {
		return err
	}
	pr, err := collab.Resolve(c.prs, ref)
	if err != nil {
		return err
	}
	found := false
	for _, e := range pr.Events {
		if e.Kind == collab.KindComment && strings.HasPrefix(e.ID, commentID) {
			commentID, found = e.ID, true
		}
	}
	if !found {
		return fmt.Errorf("no comment %s on #%d", commentID, pr.Number)
	}
	if err := c.append(&collab.Event{Kind: collab.KindResolve, PR: pr.ID, Ref: commentID}); err != nil {
		return err
	}
	a.logf("#%d: thread %s resolved", pr.Number, commentID)
	return nil
}

// PRClose closes without merging.
func (a *App) PRClose(dir, ref string) error {
	c, err := a.openPR(dir)
	if err != nil {
		return err
	}
	pr, err := collab.Resolve(c.prs, ref)
	if err != nil {
		return err
	}
	if err := c.append(&collab.Event{Kind: collab.KindState, PR: pr.ID, State: collab.StateClosed}); err != nil {
		return err
	}
	a.logf("#%d closed", pr.Number)
	return nil
}

// mergeCheck returns why a PR may not be merged, or "".
func (c *prContext) mergeCheck(pr *collab.PullRequest, head, base string) string {
	if pr.State != collab.StateOpen {
		return fmt.Sprintf("#%d is %s", pr.Number, pr.State)
	}
	pol := collab.LoadPolicy(c.r.Work, base)
	approved, changes := c.approvals(pr, head)
	if len(changes) > 0 {
		return "changes requested by " + strings.Join(changes, ", ")
	}
	if len(approved) < pol.RequiredApprovals {
		return fmt.Sprintf("needs %d approval(s) of %s, has %d", pol.RequiredApprovals, short(head), len(approved))
	}
	checks := collab.Checks(c.events, head)
	for _, req := range pol.RequiredChecks {
		e, ok := checks[req]
		if !ok {
			return fmt.Sprintf("required check %q has not run for %s", req, short(head))
		}
		if e.Status != collab.StatusSuccess {
			return fmt.Sprintf("required check %q is %s", req, e.Status)
		}
	}
	return ""
}

// PRMerge merges head into base (merge commit, --squash or --ff) in a
// temporary worktree, pushes the result and records the state change.
// Policy (approvals, required checks) is enforced here and verifiable by
// every other client, since its inputs are signed events.
func (a *App) PRMerge(dir, ref, method string) error {
	c, err := a.openPR(dir)
	if err != nil {
		return err
	}
	pr, err := collab.Resolve(c.prs, ref)
	if err != nil {
		return err
	}
	head, base := c.headSHA(pr), c.baseSHA(pr)
	if base == "" {
		return fmt.Errorf("base branch %s not found", pr.Base)
	}
	if c.isAgent {
		return errors.New("cannot merge: this device is an agent; a person has to merge")
	}
	if why := c.mergeCheck(pr, head, base); why != "" {
		return errors.New("cannot merge: " + why)
	}
	wt, err := os.MkdirTemp("", "secretree-merge-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(wt)
	defer gitx.Run(c.r.Work, "worktree", "remove", "--force", wt)
	if _, err := gitx.Run(c.r.Work, "worktree", "add", "--quiet", "--detach", wt, base); err != nil {
		return err
	}
	msg := fmt.Sprintf("Merge pull request #%d: %s", pr.Number, pr.Title)
	ident := []string{"-c", "user.name=" + c.r.Cfg.Label, "-c", "user.email=" + c.r.Cfg.Label + "@secretree"}
	switch method {
	case "", "merge":
		if _, err := gitx.Run(wt, append(ident, "merge", "--no-ff", "--no-edit", "-m", msg, head)...); err != nil {
			return fmt.Errorf("merge conflict; resolve on the branch and retry: %w", err)
		}
	case "squash":
		if _, err := gitx.Run(wt, append(ident, "merge", "--squash", head)...); err != nil {
			return fmt.Errorf("merge conflict; resolve on the branch and retry: %w", err)
		}
		if _, err := gitx.Run(wt, append(ident, "commit", "--quiet", "-m", msg)...); err != nil {
			return err
		}
	case "ff":
		if _, err := gitx.Run(wt, "merge", "--ff-only", head); err != nil {
			return fmt.Errorf("not a fast-forward: %w", err)
		}
	default:
		return fmt.Errorf("unknown merge method %q (merge, squash, ff)", method)
	}
	out, err := gitx.Run(wt, "rev-parse", "HEAD")
	if err != nil {
		return err
	}
	merged := strings.TrimSpace(out)
	if c.remote != "" {
		if _, err := gitx.Run(c.r.Work, "push", "--quiet", c.remote, merged+":refs/heads/"+pr.Base); err != nil {
			return fmt.Errorf("push merge: %w", err)
		}
	}
	// bring the local base branch along when that is safe
	cur, _ := gitx.Run(c.r.Work, "symbolic-ref", "--short", "-q", "HEAD")
	localBase, _ := gitx.Run(c.r.Work, "rev-parse", "--verify", "-q", "refs/heads/"+pr.Base)
	if strings.TrimSpace(localBase) == base {
		if strings.TrimSpace(cur) == pr.Base {
			_, _ = gitx.Run(c.r.Work, "merge", "--ff-only", "--quiet", merged)
		} else {
			_, _ = gitx.Run(c.r.Work, "update-ref", "refs/heads/"+pr.Base, merged, base)
		}
	}
	if err := c.append(&collab.Event{Kind: collab.KindState, PR: pr.ID, State: collab.StateMerged, MergeCommit: merged}); err != nil {
		return err
	}
	a.logf("#%d merged into %s as %s", pr.Number, pr.Base, short(merged))
	return nil
}

// PolicyInit writes a default .secretree/policy.json into the work tree.
func (a *App) PolicyInit(dir string, approvals int, checks []string) error {
	work, _, err := locateRepo(dir)
	if err != nil {
		return err
	}
	p := collab.PolicyPath(work)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	var b strings.Builder
	fmt.Fprintf(&b, "{\n  \"required_approvals\": %d,\n  \"required_checks\": [", approvals)
	for i, c := range checks {
		if i > 0 {
			b.WriteString(", ")
		}
		fmt.Fprintf(&b, "%q", c)
	}
	b.WriteString("]\n}\n")
	if err := os.WriteFile(p, []byte(b.String()), 0o644); err != nil {
		return err
	}
	a.logf("wrote %s; commit it on the base branch to enforce it", p)
	return nil
}

// remapLine follows a line of path from commit from to commit to through
// the diff between them. ok is false when the line itself was changed or
// removed (the comment is outdated), true with the new number otherwise.
func remapLine(dir, from, to, path string, line int) (int, bool) {
	if from == to || from == "" {
		return line, true
	}
	out, err := gitx.Run(dir, "diff", "-U0", from, to, "--", path)
	if err != nil {
		return 0, false
	}
	delta := 0
	for _, l := range strings.Split(out, "\n") {
		if !strings.HasPrefix(l, "@@") {
			continue
		}
		// @@ -oldStart[,oldLen] +newStart[,newLen] @@
		f := strings.Fields(l)
		if len(f) < 3 {
			continue
		}
		oStart, oLen := hunkRange(f[1])
		_, nLen := hunkRange(f[2])
		if oLen == 0 { // pure insertion at oStart: lines after it shift
			if line > oStart {
				delta += nLen
			}
			continue
		}
		if line >= oStart && line < oStart+oLen {
			return 0, false // the commented line was changed or deleted
		}
		if line >= oStart+oLen {
			delta += nLen - oLen
		}
	}
	return line + delta, true
}

func hunkRange(s string) (start, length int) {
	s = strings.TrimLeft(s, "-+")
	a, b, hasLen := strings.Cut(s, ",")
	fmt.Sscanf(a, "%d", &start)
	length = 1
	if hasLen {
		fmt.Sscanf(b, "%d", &length)
	}
	return
}

// pushBranch pushes one branch through the helper with the helper reachable.
func (a *App) pushBranch(work, remote, branch string) error {
	pathEnv, err := ensureHelperInPath()
	if err != nil {
		return err
	}
	cmd := exec.Command("git", "push", "--quiet", "-u", remote, branch)
	cmd.Dir = work
	cmd.Env = append(gitx.Env(), "PATH="+pathEnv)
	cmd.Stdout, cmd.Stderr = a.Err, a.Err
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("git push %s %s: %w", remote, branch, err)
	}
	return nil
}

// PRCheckout fetches a pull request's head branch and checks it out.
func (a *App) PRCheckout(dir, ref string) error {
	c, err := a.openPR(dir)
	if err != nil {
		return err
	}
	pr, err := collab.Resolve(c.prs, ref)
	if err != nil {
		return err
	}
	head := c.headSHA(pr)
	if head == "" {
		return fmt.Errorf("head branch %s of #%d is not available", pr.Head, pr.Number)
	}
	if _, err := gitx.Run(c.r.Work, "rev-parse", "--verify", "-q", "refs/heads/"+pr.Head); err == nil {
		if _, err := gitx.Run(c.r.Work, "checkout", "--quiet", pr.Head); err != nil {
			return err
		}
		if c.remote != "" {
			_, _ = gitx.Run(c.r.Work, "merge", "--ff-only", "--quiet", "refs/remotes/"+c.remote+"/"+pr.Head)
		}
	} else {
		start := head
		if c.remote != "" {
			start = "refs/remotes/" + c.remote + "/" + pr.Head
		}
		if _, err := gitx.Run(c.r.Work, "checkout", "--quiet", "-b", pr.Head, "--track", start); err != nil {
			if _, err2 := gitx.Run(c.r.Work, "checkout", "--quiet", "-b", pr.Head, head); err2 != nil {
				return err
			}
		}
	}
	a.logf("switched to %s (#%d, %s)", pr.Head, pr.Number, short(head))
	return nil
}

// PRDiff prints the diff of a pull request against its base.
func (a *App) PRDiff(dir, ref string, stat bool) error {
	c, err := a.openPR(dir)
	if err != nil {
		return err
	}
	pr, err := collab.Resolve(c.prs, ref)
	if err != nil {
		return err
	}
	head, base := c.headSHA(pr), c.baseSHA(pr)
	args := []string{"diff"}
	if stat {
		args = append(args, "--stat")
	}
	if pr.State == collab.StateMerged && pr.MergeCommit != "" {
		a.logf("merged as %s", short(pr.MergeCommit))
		args = append(args, pr.MergeCommit+"^1", pr.MergeCommit)
	} else {
		args = append(args, base+"..."+head)
	}
	out, err := gitx.Run(c.r.Work, args...)
	if err != nil {
		return err
	}
	fmt.Fprint(a.Out, out)
	return nil
}

// reportRemovals tells the user about event files a remote writer dropped
// and this client restored. Loud on purpose: it is either a mistake or an
// attempt to make a review disappear.
func (a *App) reportRemovals(rs []collab.Removal) {
	for _, r := range rs {
		a.logf("WARNING: %s was removed upstream by %s (%s); restored from local objects", r.Path, r.Author, r.Commit)
	}
}
