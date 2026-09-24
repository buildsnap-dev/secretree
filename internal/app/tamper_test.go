package app

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/buildsnap-dev/secretree/internal/collab"
)

// TestDeletedEventsComeBack: a member rewrites the collab ref to drop a
// review comment and pushes; the next sync on any other device restores
// the comment and names the deleting commit.
func TestDeletedEventsComeBack(t *testing.T) {
	homeA := env(t)
	src := newSource(t, homeA)
	vaultDir := filepath.Join(homeA, "vault.git")
	a, out := newApp()
	if err := a.Init(InitOptions{Dir: src, VaultURL: vaultDir, KitOut: filepath.Join(homeA, "kit.txt"), Push: true, Label: "app", Name: "alice"}); err != nil {
		t.Fatalf("init: %v\n%s", err, out)
	}
	if err := a.PROpen(PROpenOptions{Dir: src, Title: "Feature", Head: "feature", Base: "main"}); err != nil {
		t.Fatal(err)
	}
	if err := a.PRComment(src, "1", "this must not disappear", "", 0); err != nil {
		t.Fatal(err)
	}
	// bob joins and syncs
	homeB := filepath.Join(homeA, "bob")
	os.MkdirAll(homeB, 0o755)
	t.Setenv("SECRETREE_HOME", filepath.Join(homeB, "sg"))
	if err := a.Join(JoinOptions{VaultURL: vaultDir, Name: "bob"}); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SECRETREE_HOME", filepath.Join(homeA, "sg"))
	if err := a.MemberApprove(src, "bob", ""); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SECRETREE_HOME", filepath.Join(homeB, "sg"))
	bob := filepath.Join(homeB, "app")
	if err := a.Clone(CloneOptions{VaultURL: vaultDir, Dir: bob}); err != nil {
		t.Fatalf("clone: %v\n%s", err, out)
	}
	out.Reset()
	if err := a.PRShow(bob, "1"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "this must not disappear") {
		t.Fatalf("bob should see the comment:\n%s", out)
	}

	// bob (or malware on bob's machine) rewrites the collab ref without the comment and pushes it
	tip := git(t, bob, "rev-parse", collab.Ref)
	files := strings.Fields(git(t, bob, "ls-tree", "-r", "--name-only", collab.Ref))
	var victim string
	for _, f := range files {
		if strings.HasSuffix(f, ".json") && strings.Contains(git(t, bob, "show", collab.Ref+":"+f), "this must not disappear") {
			victim = f
		}
	}
	if victim == "" {
		t.Fatal("comment file not found")
	}
	idx := filepath.Join(homeB, "idx")
	gitEnv := func(args ...string) string {
		t.Helper()
		out, err := gitxRunEnv(bob, []string{"GIT_INDEX_FILE=" + idx}, args...)
		if err != nil {
			t.Fatalf("git %v: %v", args, err)
		}
		return strings.TrimSpace(out)
	}
	gitEnv("read-tree", tip)
	gitEnv("update-index", "--force-remove", victim, victim+".sig")
	tree := gitEnv("write-tree")
	evilOut, err := gitxRunEnv(bob, []string{"GIT_AUTHOR_NAME=mallory", "GIT_COMMITTER_NAME=mallory"}, "commit-tree", tree, "-p", tip, "-m", "cleanup")
	if err != nil {
		t.Fatal(err)
	}
	evil := strings.TrimSpace(evilOut)
	git(t, bob, "update-ref", collab.Ref, evil)
	if o, err := gitOut(bob, "push", "origin", collab.Ref+":"+collab.Ref); err != nil {
		t.Fatalf("evil push: %v\n%s", err, o)
	}

	// alice syncs: the comment is back and the deletion is reported
	t.Setenv("SECRETREE_HOME", filepath.Join(homeA, "sg"))
	out.Reset()
	if err := a.PRShow(src, "1"); err != nil {
		t.Fatalf("show: %v\n%s", err, out)
	}
	if !strings.Contains(out.String(), "this must not disappear") {
		t.Fatalf("comment should be restored on alice's side:\n%s", out)
	}
	if !strings.Contains(out.String(), "WARNING") || !strings.Contains(out.String(), "mallory") {
		t.Logf("alice collab log:\n%s", git(t, src, "log", "--format=%h %an %s", collab.Ref))
		t.Fatalf("deletion should be reported with the author:\n%s", out)
	}
	// and bob, after his next sync, has it again too
	t.Setenv("SECRETREE_HOME", filepath.Join(homeB, "sg"))
	out.Reset()
	if err := a.PRShow(bob, "1"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "this must not disappear") {
		t.Fatalf("comment should be back on bob's side:\n%s", out)
	}
}

// TestVaultRollbackDetectedAndRepaired: the host drops the newest
// generations; clients refuse to continue; repair rebuilds from the mirror
// and the chain verifies again with every ref and the collab history.
func TestVaultRollbackDetectedAndRepaired(t *testing.T) {
	home := env(t)
	src := newSource(t, home)
	vaultDir := filepath.Join(home, "vault.git")
	a, out := newApp()
	if err := a.Init(InitOptions{Dir: src, VaultURL: vaultDir, KitOut: filepath.Join(home, "kit.txt"), Push: true, Name: "alice"}); err != nil {
		t.Fatalf("init: %v\n%s", err, out)
	}
	if err := a.PROpen(PROpenOptions{Dir: src, Title: "Feature", Head: "feature", Base: "main"}); err != nil {
		t.Fatal(err)
	}
	commit(t, src, "x.txt", "x\n", "more work")
	if o, err := gitOut(src, "push", "origin", "main"); err != nil {
		t.Fatalf("push: %v\n%s", err, o)
	}
	// the host loses the last two generations
	git(t, vaultDir, "config", "receive.denyNonFastForwards", "false")
	git(t, vaultDir, "config", "receive.denyDeletes", "false")
	git(t, vaultDir, "update-ref", "refs/heads/main", "refs/heads/main~2")

	if o, err := gitOut(src, "fetch", "origin"); err == nil || !strings.Contains(o, "rolled back") {
		t.Fatalf("fetch must refuse a rolled-back vault:\n%s", o)
	}
	if err := a.PRList(src, false); err == nil || !strings.Contains(err.Error(), "rolled back") {
		t.Fatalf("pr commands must refuse too: %v", err)
	}
	out.Reset()
	if err := a.Repair(src); err != nil {
		t.Fatalf("repair: %v\n%s", err, out)
	}
	if !strings.Contains(out.String(), "restore proof OK") {
		t.Fatalf("repair output:\n%s", out)
	}
	// everything works again and nothing was lost
	if o, err := gitOut(src, "fetch", "origin"); err != nil {
		t.Fatalf("fetch after repair: %v\n%s", err, o)
	}
	out.Reset()
	if err := a.PRList(src, true); err != nil {
		t.Fatalf("pr list after repair: %v", err)
	}
	if !strings.Contains(out.String(), "Feature") {
		t.Fatalf("collab history should survive the repair:\n%s", out)
	}
	if err := a.Verify(VerifyOptions{Dir: src, Quick: true}); err != nil {
		t.Fatalf("verify after repair: %v", err)
	}
}
