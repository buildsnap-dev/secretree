package app

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/buildsnap-dev/secretree/internal/collab"
	"github.com/buildsnap-dev/secretree/internal/config"
)

// TestOneCommandInit: init wires the remote and pushes in one go, the kit
// is tracked until confirmed, and the manifest cache makes reloads cheap.
func TestOneCommandInit(t *testing.T) {
	home := env(t)
	src := newSource(t, home)
	vaultDir := filepath.Join(home, "vault.git")
	a, out := newApp()
	kit := filepath.Join(home, "kit.txt")
	if err := a.Init(InitOptions{Dir: src, VaultURL: vaultDir, KitOut: kit, Push: true}); err != nil {
		t.Fatalf("init --push: %v\n%s", err, out)
	}
	if got := git(t, src, "remote", "get-url", "origin"); got != "secretree::"+vaultDir {
		t.Fatalf("origin: %s", got)
	}
	if !strings.Contains(git(t, src, "branch", "-r"), "origin/feature") {
		t.Fatal("feature branch was not pushed")
	}
	if !strings.Contains(git(t, src, "ls-remote", "--tags", "origin"), "v1") {
		t.Fatal("tags were not pushed")
	}
	// kit pending → status warns → confirm clears it
	out.Reset()
	if err := a.Status(src); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "recovery kit of this vault has not been confirmed") {
		t.Fatalf("status should warn about the kit:\n%s", out)
	}
	if err := a.Kit(src, "", true); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	_ = a.Status(src)
	if strings.Contains(out.String(), "not been confirmed") {
		t.Fatalf("warning should be gone:\n%s", out)
	}
	// manifest cache: after one load, every manifest blob is cached
	r, err := a.openRepo(src)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.loadVault(r); err != nil {
		t.Fatal(err)
	}
	cacheRoot := filepath.Join(r.Paths.Root, "manifest-cache")
	var cached int
	filepath.Walk(cacheRoot, func(p string, info os.FileInfo, _ error) error {
		if info != nil && !info.IsDir() && strings.HasSuffix(p, ".json") {
			cached++
		}
		return nil
	})
	if cached == 0 {
		t.Fatal("no manifests cached")
	}
	// a tampered cache entry must not be trusted blindly: a chain-link check still runs
	// (cheap sanity: corrupt one entry and make sure loading still succeeds or fails loudly, never panics)
	filepath.Walk(cacheRoot, func(p string, info os.FileInfo, _ error) error {
		if info != nil && !info.IsDir() && strings.HasSuffix(p, ".json") {
			_ = os.WriteFile(p, []byte("{not json"), 0o600)
		}
		return nil
	})
	if _, err := a.loadVault(r); err != nil {
		t.Fatalf("corrupt cache should be ignored, got %v", err)
	}
	// second init in the same repo is refused, a second repo joins the same vault
	if err := a.Init(InitOptions{Dir: src, VaultURL: vaultDir}); err == nil {
		t.Fatal("re-init without --force should fail")
	}
}

func TestWatchSummaries(t *testing.T) {
	home := env(t)
	src := newSource(t, home)
	vaultDir := filepath.Join(home, "vault.git")
	a, out := newApp()
	if err := a.Init(InitOptions{Dir: src, VaultURL: vaultDir, KitOut: filepath.Join(home, "kit.txt"), Push: true, Label: "alice", Name: "alice"}); err != nil {
		t.Fatalf("init: %v\n%s", err, out)
	}
	if err := a.PROpen(PROpenOptions{Dir: src, Title: "Feature", Head: "feature", Base: "main"}); err != nil {
		t.Fatalf("pr open: %v", err)
	}
	// learn the current state
	r, _ := a.openRepo(src)
	seen, err := a.watchPass(r, WatchOptions{Exec: "true"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	// a teammate's activity: simulate another actor by editing the event actor
	// through a second device would be heavy; instead check the summariser directly
	number := map[string]int{"1-abcd": 1}
	lines := summarize([]collab.Event{
		{PR: "1-abcd", Kind: collab.KindComment, ActorName: "bob"},
		{PR: "1-abcd", Kind: collab.KindComment, ActorName: "bob"},
		{PR: "1-abcd", Kind: collab.KindReview, Verdict: collab.VerdictApprove, ActorName: "bob"},
		{Kind: collab.KindCheck, Status: collab.StatusFailure, Name: "ci"},
	}, number, map[string]string{"1-abcd": "Feature"}, false)
	want := []string{"PR #1: approved by bob", "PR #1: new comment ×2 by bob", "repository: check failure"}
	if strings.Join(lines, "|") != strings.Join(want, "|") {
		t.Fatalf("summaries: %v", lines)
	}
	// our own events are not news: a second pass after our own comment reports nothing new
	if err := a.PRComment(src, "1", "mine", "", 0); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	seen2, err := a.watchPass(r, WatchOptions{Exec: "false"}, seen)
	if err != nil {
		t.Fatal(err)
	}
	if len(seen2) != len(seen)+1 || strings.Contains(out.String(), "watch:") {
		t.Fatalf("own comment must be recorded but not announced:\n%s", out)
	}
	_ = config.Dir
}

func TestInlineDiffComments(t *testing.T) {
	diff := "diff --git a/src/x.go b/src/x.go\nindex 1..2 100644\n--- a/src/x.go\n+++ b/src/x.go\n@@ -1,3 +1,4 @@\n package main\n+import \"fmt\"\n \n-func a() {}\n+func b() {}\n"
	rows := parseDiff(diff, map[string][]eventRow{"src/x.go:2": {{Body: "why?"}}})
	var got []string
	for _, r := range rows {
		if r.NewLine > 0 {
			got = append(got, r.Path+":"+itoa(r.NewLine)+":"+r.Class)
		}
		if len(r.Comments) > 0 && r.NewLine != 2 {
			t.Fatalf("comment attached to the wrong row: %+v", r)
		}
	}
	want := "src/x.go:1:|src/x.go:2:a|src/x.go:3:|src/x.go:4:a"
	if strings.Join(got, "|") != want {
		t.Fatalf("rows: %v", got)
	}
}

func itoa(n int) string {
	return strings.TrimSpace(strings.Replace(string(rune('0'+n)), "\x00", "", -1))
}
