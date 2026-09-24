package app

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/buildsnap-dev/secretree/internal/collab"
)

// TestPullRequestFlow drives a PR through two devices, policy, CI and CD.
func TestPullRequestFlow(t *testing.T) {
	homeA := env(t)
	src := newSource(t, homeA)
	vaultDir := filepath.Join(homeA, "vault.git")
	a, out := newApp()
	if err := a.Init(InitOptions{Dir: src, VaultURL: vaultDir, KitOut: filepath.Join(homeA, "kit.txt"), Label: "alice", Name: "alice"}); err != nil {
		t.Fatalf("init: %v\n%s", err, out)
	}
	// policy: one approval and a green "ci" check
	if err := a.PolicyInit(src, 1, []string{"ci"}); err != nil {
		t.Fatal(err)
	}
	// a pipeline the runner will find on its own
	write(t, src, ".secretree/ci", "#!/bin/sh\ntest -f README.md && echo ok\n")
	if err := os.Chmod(filepath.Join(src, ".secretree", "ci"), 0o755); err != nil {
		t.Fatal(err)
	}
	git(t, src, "add", "-A")
	git(t, src, "commit", "-qm", "policy and ci")
	if o, err := gitOut(src, "push", "-u", "origin", "--all"); err != nil {
		t.Fatalf("push: %v\n%s", err, o)
	}

	// Bob joins on his own device
	homeB := filepath.Join(homeA, "bob")
	os.MkdirAll(homeB, 0o755)
	t.Setenv("SECRETREE_HOME", filepath.Join(homeB, "sg"))
	req := filepath.Join(homeB, "join.txt")
	if err := a.Join(JoinOptions{VaultURL: vaultDir, Name: "bob", Out: req, NoPush: true}); err != nil {
		t.Fatalf("join: %v\n%s", err, out)
	}
	t.Setenv("SECRETREE_HOME", filepath.Join(homeA, "sg"))
	if err := a.MemberAdd(MemberOptions{Dir: src, Request: req}); err != nil {
		t.Fatalf("member add: %v\n%s", err, out)
	}
	t.Setenv("SECRETREE_HOME", filepath.Join(homeB, "sg"))
	bob := filepath.Join(homeB, "app")
	if err := a.Clone(CloneOptions{VaultURL: vaultDir, Dir: bob}); err != nil {
		t.Fatalf("clone: %v\n%s", err, out)
	}

	// Alice opens a PR from a pushed branch
	t.Setenv("SECRETREE_HOME", filepath.Join(homeA, "sg"))
	git(t, src, "checkout", "-qb", "topic")
	commit(t, src, "topic.txt", "topic\n", "topic work")
	if o, err := gitOut(src, "push", "origin", "topic"); err != nil {
		t.Fatalf("push topic: %v\n%s", err, o)
	}
	out.Reset()
	if err := a.PROpen(PROpenOptions{Dir: src, Title: "Add topic", Body: "please review"}); err != nil {
		t.Fatalf("pr open: %v\n%s", err, out)
	}
	if !strings.Contains(out.String(), "pull request #1 opened") {
		t.Fatalf("open output:\n%s", out)
	}
	// not mergeable yet: policy wants an approval and ci
	if err := a.PRMerge(src, "#1", "merge"); err == nil || !strings.Contains(err.Error(), "cannot merge") {
		t.Fatalf("merge should be blocked: %v", err)
	}

	// Bob and Alice comment at the same time (both on stale collab state)
	if err := a.PRComment(src, "1", "alice here", "topic.txt", 1); err != nil {
		t.Fatalf("alice comment: %v", err)
	}
	t.Setenv("SECRETREE_HOME", filepath.Join(homeB, "sg"))
	if err := a.PRComment(bob, "1", "bob here", "", 0); err != nil {
		t.Fatalf("bob comment: %v", err)
	}
	// Bob approves
	if err := a.PRReview(bob, "#1", collab.VerdictApprove, "lgtm"); err != nil {
		t.Fatalf("approve: %v", err)
	}
	out.Reset()
	if err := a.PRShow(bob, "1"); err != nil {
		t.Fatalf("show: %v", err)
	}
	if !strings.Contains(out.String(), "alice here") || !strings.Contains(out.String(), "bob here") || !strings.Contains(out.String(), "approvals: 1/1") {
		t.Fatalf("show after union merge:\n%s", out)
	}

	// the runner (on Bob's machine) finds the pipeline and records a green check
	out.Reset()
	if err := a.Runner(RunnerOptions{Dir: bob, Once: true}); err != nil {
		t.Fatalf("runner: %v\n%s", err, out)
	}
	if !strings.Contains(out.String(), "→ success") {
		t.Fatalf("runner output:\n%s", out)
	}
	// a second pass does nothing (checks are per commit)
	out.Reset()
	if err := a.Runner(RunnerOptions{Dir: bob, Once: true}); err != nil {
		t.Fatalf("runner 2: %v\n%s", err, out)
	}
	if strings.Contains(out.String(), "job(s) done") {
		t.Fatalf("runner should be idle:\n%s", out)
	}

	// Alice merges now that policy passes; deploy agent ships main
	t.Setenv("SECRETREE_HOME", filepath.Join(homeA, "sg"))
	git(t, src, "checkout", "-q", "main")
	out.Reset()
	if err := a.PRMerge(src, "1", "merge"); err != nil {
		t.Fatalf("merge: %v\n%s", err, out)
	}
	if git(t, src, "log", "-1", "--format=%s") != "Merge pull request #1: Add topic" {
		t.Fatalf("local main not advanced: %s", git(t, src, "log", "-1", "--format=%s"))
	}
	out.Reset()
	if err := a.PRList(src, true); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "merged") {
		t.Fatalf("list:\n%s", out)
	}
	target := filepath.Join(homeA, "deployed")
	// main's new tip has no ci check yet: deploy must wait...
	if err := a.DeployAgent(DeployOptions{Dir: src, To: target, Once: true, RequireCheck: "ci"}); err != nil {
		t.Fatalf("deploy: %v", err)
	}
	if _, err := os.Stat(filepath.Join(target, "topic.txt")); err == nil {
		t.Fatal("deployed without a green check")
	}
	// ...until the runner checks main
	if err := a.Runner(RunnerOptions{Dir: src, Once: true}); err != nil {
		t.Fatalf("runner on main: %v\n%s", err, out)
	}
	out.Reset()
	if err := a.DeployAgent(DeployOptions{Dir: src, To: target, Once: true, RequireCheck: "ci", Cmd: "echo deployed > .hook-ran"}); err != nil {
		t.Fatalf("deploy: %v\n%s", err, out)
	}
	for _, f := range []string{"topic.txt", "README.md", ".hook-ran"} {
		if _, err := os.Stat(filepath.Join(target, f)); err != nil {
			t.Fatalf("%s missing after deploy", f)
		}
	}
	if _, err := os.Stat(filepath.Join(target, ".git")); err == nil {
		t.Fatal("deploy exported a .git directory")
	}
	// the deploy event is visible to Bob as a signed fact
	t.Setenv("SECRETREE_HOME", filepath.Join(homeB, "sg"))
	c, err := a.openPR(bob)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range c.events {
		if e.Kind == collab.KindDeploy && e.Status == collab.StatusSuccess && e.ActorName == "alice" {
			found = true
		}
	}
	if !found {
		t.Fatal("deploy event not visible to bob")
	}
}
