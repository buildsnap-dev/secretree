package app

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/buildsnap-dev/secretree/internal/config"
	"github.com/buildsnap-dev/secretree/internal/gitx"
)

var helperDir string

// TestMain builds the real binary once so git can spawn it as a remote helper.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "secretree-helper-")
	if err != nil {
		panic(err)
	}
	exe := filepath.Join(dir, "secretree")
	goBin, err := exec.LookPath("go")
	if err != nil {
		panic("go not on PATH: " + err.Error())
	}
	build := exec.Command(goBin, "build", "-o", exe, "../../cmd/secretree")
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		panic("build: " + err.Error())
	}
	if err := os.Symlink(exe, filepath.Join(dir, HelperName)); err != nil {
		panic(err)
	}
	helperDir = dir
	os.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

// assertCloneOf checks that b is a clone of a: same main tip, same tags,
// same work tree (remote-tracking refs are git's own business).
func assertCloneOf(t *testing.T, a, b string) {
	t.Helper()
	if git(t, a, "rev-parse", "main") != git(t, b, "rev-parse", "main") {
		t.Fatal("main differs")
	}
	if git(t, a, "tag") != git(t, b, "tag") {
		t.Fatal("tags differ")
	}
	for _, br := range strings.Fields(git(t, a, "for-each-ref", "--format=%(refname:short)", "refs/heads/")) {
		if git(t, a, "rev-parse", br) != git(t, b, "rev-parse", "origin/"+br) {
			t.Fatalf("branch %s differs from origin/%s in clone", br, br)
		}
	}
	cmd := exec.Command("diff", "-r", "--exclude=.git", a, b)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("working trees differ:\n%s", out)
	}
}

// gitOut runs git and returns combined output and error (for expected failures).
func gitOut(dir string, args ...string) (string, error) {
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = gitx.Env()
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func TestRemoteHelperRoundTrip(t *testing.T) {
	home := env(t)
	src := newSource(t, home)
	vaultDir := filepath.Join(home, "vault.git")
	a, out := newApp()
	if err := a.Init(InitOptions{Dir: src, VaultURL: vaultDir, KitOut: filepath.Join(home, "kit.txt"), Label: "app"}); err != nil {
		t.Fatalf("init: %v\n%s", err, out)
	}

	// push through the helper: first generation is written from the mirror
	if o, err := gitOut(src, "push", "-u", "origin", "--all"); err != nil {
		t.Fatalf("push --all: %v\n%s", err, o)
	}
	if o, err := gitOut(src, "push", "origin", "--tags"); err != nil {
		t.Fatalf("push --tags: %v\n%s", err, o)
	}
	if _, err := gitOut(src, "push", "origin"); err != nil { // nothing new: "Everything up-to-date"
		t.Fatalf("idempotent push: %v", err)
	}

	// second machine: clone through the helper (same key store here)
	b := filepath.Join(home, "b")
	if err := a.Clone(CloneOptions{VaultURL: vaultDir, Dir: b}); err != nil {
		t.Fatalf("clone: %v\n%s", err, out)
	}
	assertCloneOf(t, src, b)
	if got := git(t, b, "remote", "get-url", "origin"); got != "secretree::"+vaultDir {
		t.Fatalf("origin url: %s", got)
	}
	if got := git(t, b, "tag"); !strings.Contains(got, "v1") {
		t.Fatalf("tags not cloned: %q", got)
	}

	// b commits and pushes; a pulls
	commit(t, b, "from-b.txt", "b\n", "from b")
	if o, err := gitOut(b, "push", "origin", "main"); err != nil {
		t.Fatalf("push from b: %v\n%s", err, o)
	}
	if o, err := gitOut(src, "pull", "--ff-only", "origin", "main"); err != nil {
		t.Fatalf("pull on a: %v\n%s", err, o)
	}
	if _, err := os.Stat(filepath.Join(src, "from-b.txt")); err != nil {
		t.Fatal("a did not receive b's commit")
	}

	// a stale non-fast-forward push is refused like any git remote would
	git(t, b, "commit", "--amend", "-q", "-m", "rewritten")
	if o, err := gitOut(b, "push", "origin", "main"); err == nil || !strings.Contains(o, "rejected") {
		t.Fatalf("non-ff push should be rejected:\n%s", o)
	}
	if o, err := gitOut(b, "push", "--force", "origin", "main"); err != nil {
		t.Fatalf("force push: %v\n%s", err, o)
	}
	// a's history is now behind a rewrite; fetch shows the forced update
	if o, err := gitOut(src, "fetch", "origin"); err != nil {
		t.Fatalf("fetch after force: %v\n%s", err, o)
	}
	if git(t, src, "rev-parse", "origin/main") != git(t, b, "rev-parse", "main") {
		t.Fatal("origin/main on a does not match b's main after force push")
	}

	// branch deletion is a generation without a bundle
	if o, err := gitOut(b, "push", "origin", ":feature"); err != nil {
		t.Fatalf("delete branch: %v\n%s", err, o)
	}
	if o, err := gitOut(src, "fetch", "--prune", "origin"); err != nil {
		t.Fatalf("fetch --prune: %v\n%s", err, o)
	}
	if o, _ := gitOut(src, "branch", "-r"); strings.Contains(o, "origin/feature") {
		t.Fatalf("feature branch should be gone on a:\n%s", o)
	}

	// the vault chain is intact and verifiable
	out.Reset()
	if err := a.Verify(VerifyOptions{Dir: b}); err != nil {
		t.Fatalf("verify: %v\n%s", err, out)
	}
	if !strings.Contains(out.String(), "rebuilt from the remote") {
		t.Fatalf("verify output:\n%s", out)
	}
	// and a restore from the kit reproduces b's work tree
	home2 := env(t)
	restored := filepath.Join(home2, "restored")
	if err := a.Restore(RestoreOptions{VaultURL: vaultDir, To: restored, KitIn: filepath.Join(home, "kit.txt")}); err != nil {
		t.Fatalf("restore: %v\n%s", err, out)
	}
	git(t, b, "checkout", "-q", "main")
	rb, _ := gitx.RefMap(b)
	rr, _ := gitx.RefMap(restored)
	for _, ref := range []string{"refs/heads/main", "refs/tags/v1"} {
		if rb[ref] != rr[ref] {
			t.Fatalf("%s differs after restore: %s vs %s", ref, rb[ref], rr[ref])
		}
	}
}

func TestVaultLevelConflict(t *testing.T) {
	home := env(t)
	src := newSource(t, home)
	vaultDir := filepath.Join(home, "vault.git")
	a, out := newApp()
	if err := a.Init(InitOptions{Dir: src, VaultURL: vaultDir, KitOut: filepath.Join(home, "kit.txt")}); err != nil {
		t.Fatalf("init: %v\n%s", err, out)
	}
	if o, err := gitOut(src, "push", "-u", "origin", "main"); err != nil {
		t.Fatalf("push: %v\n%s", err, o)
	}
	b := filepath.Join(home, "b")
	if err := a.Clone(CloneOptions{VaultURL: vaultDir, Dir: b}); err != nil {
		t.Fatalf("clone: %v\n%s", err, out)
	}

	// b has synced its view of the vault...
	rb, err := a.openRepo(b)
	if err != nil {
		t.Fatal(err)
	}
	vs, err := a.loadVault(rb)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.mirrorSync(rb, vs); err != nil {
		t.Fatal(err)
	}
	// ...then a pushes a generation in the meantime...
	commit(t, src, "race.txt", "a\n", "a wins")
	if o, err := gitOut(src, "push", "origin", "main"); err != nil {
		t.Fatalf("push: %v\n%s", err, o)
	}
	// ...and b tries to append on its stale view: the host's CAS refuses
	commit(t, b, "race.txt", "b\n", "b loses")
	git(t, b, "push", "-q", rb.Paths.Mirror, "main")
	status, _ := config.LoadStatus(rb.Paths)
	_, err = a.writeGeneration(rb, vs, status, genOptions{Source: rb.Paths.Mirror})
	if !errors.Is(err, errPushRejected) {
		t.Fatalf("expected vault rejection, got %v", err)
	}
	// after a fetch the conflict is an ordinary git conflict on b
	if o, err := gitOut(b, "fetch", "origin"); err != nil {
		t.Fatalf("fetch: %v\n%s", err, o)
	}
	if git(t, b, "rev-parse", "origin/main") != git(t, src, "rev-parse", "main") {
		t.Fatal("b should see a's commit after fetch")
	}
	if o, err := gitOut(b, "push", "origin", "main"); err == nil || !strings.Contains(o, "rejected") {
		t.Fatalf("b's push must be non-fast-forward now:\n%s", o)
	}
}
