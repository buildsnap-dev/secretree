package app

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/buildsnap-dev/secretree/internal/collab"
)

func TestRemapLine(t *testing.T) {
	home := env(t)
	src := newSource(t, home)
	// file with 6 lines
	write(t, src, "f.txt", "a\nb\nc\nd\ne\nf\n")
	git(t, src, "add", "f.txt")
	git(t, src, "commit", "-qm", "six lines")
	c1 := git(t, src, "rev-parse", "HEAD")
	// insert two lines at the top, change line "d", delete "f"
	write(t, src, "f.txt", "x\ny\na\nb\nc\nD\ne\n")
	git(t, src, "commit", "-qam", "edit")
	c2 := git(t, src, "rev-parse", "HEAD")
	cases := []struct {
		line int
		want int
		ok   bool
	}{{1, 3, true}, {2, 4, true}, {3, 5, true}, {4, 0, false}, {5, 7, true}, {6, 0, false}}
	for _, c := range cases {
		got, ok := remapLine(src, c1, c2, "f.txt", c.line)
		if ok != c.ok || (ok && got != c.want) {
			t.Errorf("line %d: got %d,%v want %d,%v", c.line, got, ok, c.want, c.ok)
		}
	}
	if got, ok := remapLine(src, c1, c1, "f.txt", 4); !ok || got != 4 {
		t.Errorf("same commit must be identity")
	}
}

// TestAgentMember: an agent reviews via the runner with PR context, its
// approval does not count, it cannot merge, threads resolve, a ledger
// entry records the export.
func TestAgentMember(t *testing.T) {
	homeA := env(t)
	src := newSource(t, homeA)
	vaultDir := filepath.Join(homeA, "vault.git")
	a, out := newApp()
	if err := a.Init(InitOptions{Dir: src, VaultURL: vaultDir, KitOut: filepath.Join(homeA, "kit.txt"), Label: "alice", Name: "alice", Push: true}); err != nil {
		t.Fatalf("init: %v\n%s", err, out)
	}
	if err := a.PolicyInit(src, 1, nil); err != nil {
		t.Fatal(err)
	}
	git(t, src, "add", "-A")
	git(t, src, "commit", "-qm", "policy")
	if o, err := gitOut(src, "push", "origin", "main"); err != nil {
		t.Fatalf("push: %v\n%s", err, o)
	}
	if err := a.PROpen(PROpenOptions{Dir: src, Title: "Feature", Head: "feature", Base: "main"}); err != nil {
		t.Fatal(err)
	}

	// the agent joins on its own machine and is added with --role agent
	homeBot := filepath.Join(homeA, "bot")
	os.MkdirAll(homeBot, 0o755)
	t.Setenv("SECRETREE_HOME", filepath.Join(homeBot, "sg"))
	req := filepath.Join(homeBot, "join.txt")
	if err := a.Join(JoinOptions{VaultURL: vaultDir, Name: "review-bot", Out: req, NoPush: true}); err != nil {
		t.Fatalf("join: %v", err)
	}
	t.Setenv("SECRETREE_HOME", filepath.Join(homeA, "sg"))
	if err := a.MemberAdd(MemberOptions{Dir: src, Request: req, Role: "agent"}); err != nil {
		t.Fatalf("member add: %v\n%s", err, out)
	}
	t.Setenv("SECRETREE_HOME", filepath.Join(homeBot, "sg"))
	bot := filepath.Join(homeBot, "app")
	if err := a.Clone(CloneOptions{VaultURL: vaultDir, Dir: bot}); err != nil {
		t.Fatalf("clone: %v\n%s", err, out)
	}
	// a fake model: the runner job posts a line comment, a verdict and a ledger entry using the PR env
	script := filepath.Join(homeBot, "review.sh")
	write(t, homeBot, "review.sh", `#!/bin/sh
set -e
test -n "$SECRETREE_PR" || { echo "no pr"; exit 1; }
test -n "$SECRETREE_BASE" && test -n "$SECRETREE_COMMIT"
git diff "$SECRETREE_BASE...$SECRETREE_COMMIT" | grep -q '^+feature' 
secretree -C "$SECRETREE_REPO_DIR" ledger add --kind export --subject "diff of PR #$SECRETREE_PR → fake-model" >/dev/null
secretree -C "$SECRETREE_REPO_DIR" pr comment "$SECRETREE_PR" --path f.txt --line 1 -m "consider a constant" >/dev/null
secretree -C "$SECRETREE_REPO_DIR" pr review "$SECRETREE_PR" --verdict approve -m "looks fine to a robot" >/dev/null
echo reviewed
`)
	os.Chmod(script, 0o755)
	out.Reset()
	if err := a.Runner(RunnerOptions{Dir: bot, Once: true, Name: "ai-review", Cmd: script}); err != nil {
		t.Fatalf("runner: %v\n%s", err, out)
	}
	if !strings.Contains(out.String(), "→ success") {
		t.Fatalf("agent job failed:\n%s", out)
	}
	// the agent's approval does not count; alice cannot merge yet
	t.Setenv("SECRETREE_HOME", filepath.Join(homeA, "sg"))
	if err := a.PRMerge(src, "1", "merge"); err == nil || !strings.Contains(err.Error(), "needs 1 approval") {
		t.Fatalf("agent approval must not count: %v", err)
	}
	out.Reset()
	if err := a.PRShow(src, "1"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "[agent]") || !strings.Contains(out.String(), "consider a constant") {
		t.Fatalf("show:\n%s", out)
	}
	// the agent itself cannot merge even with a human approval
	if err := a.PRReview(src, "1", collab.VerdictApprove, "ok"); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SECRETREE_HOME", filepath.Join(homeBot, "sg"))
	if err := a.PRMerge(bot, "1", "merge"); err == nil || !strings.Contains(err.Error(), "agent") {
		t.Fatalf("agent must not merge: %v", err)
	}
	// resolve the agent's thread; ledger shows the export
	t.Setenv("SECRETREE_HOME", filepath.Join(homeA, "sg"))
	c, err := a.openPR(src)
	if err != nil {
		t.Fatal(err)
	}
	pr, _ := collab.Resolve(c.prs, "1")
	var commentID string
	for _, e := range pr.Events {
		if e.Kind == collab.KindComment {
			commentID = e.ID
		}
	}
	if err := a.PRResolve(src, "1", commentID[:4]); err != nil {
		t.Fatalf("resolve: %v", err)
	}
	out.Reset()
	_ = a.PRShow(src, "1")
	if !strings.Contains(out.String(), "[resolved by alice]") {
		t.Fatalf("resolved mark missing:\n%s", out)
	}
	out.Reset()
	if err := a.Ledger(src); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "export") || !strings.Contains(out.String(), "fake-model") {
		t.Fatalf("ledger:\n%s", out)
	}
	// the human approval counts: merge succeeds
	if err := a.PRMerge(src, "1", "merge"); err != nil {
		t.Fatalf("merge: %v", err)
	}
}
