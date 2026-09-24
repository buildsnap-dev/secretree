package app

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/buildsnap-dev/secretree/internal/gitx"
	"github.com/buildsnap-dev/secretree/internal/vault"
)

// env isolates the key store and HOME so tests never touch a real Keychain.
func env(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("SECRETREE_HOME", filepath.Join(home, "sg"))
	t.Setenv("SECRETREE_KEYSTORE", "file")
	t.Setenv("GIT_AUTHOR_NAME", "t")
	t.Setenv("GIT_AUTHOR_EMAIL", "t@example.com")
	t.Setenv("GIT_COMMITTER_NAME", "t")
	t.Setenv("GIT_COMMITTER_EMAIL", "t@example.com")
	t.Setenv("GIT_CONFIG_GLOBAL", filepath.Join(home, "gitconfig"))
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	return home
}

func git(t *testing.T, dir string, args ...string) string {
	t.Helper()
	out, err := gitx.Run(dir, args...)
	if err != nil {
		t.Fatalf("git %v: %v", args, err)
	}
	return strings.TrimSpace(out)
}

func write(t *testing.T, dir, name, content string) {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func commit(t *testing.T, dir, name, content, msg string) {
	t.Helper()
	write(t, dir, name, content)
	git(t, dir, "add", "-A")
	git(t, dir, "commit", "-q", "-m", msg)
}

func newSource(t *testing.T, home string) string {
	src := filepath.Join(home, "src")
	if err := os.MkdirAll(src, 0o755); err != nil {
		t.Fatal(err)
	}
	git(t, src, "init", "-q", "-b", "main")
	commit(t, src, "README.md", "hello\n", "first")
	commit(t, src, "a/b.txt", "b\n", "second")
	git(t, src, "tag", "-a", "v1", "-m", "v1")
	git(t, src, "checkout", "-q", "-b", "feature")
	commit(t, src, "f.txt", "feature\n", "feature work")
	git(t, src, "checkout", "-q", "main")
	return src
}

func newApp() (*App, *bytes.Buffer) {
	var out bytes.Buffer
	return &App{Out: &out, Err: &out, Verbose: true}, &out
}

// snapshot compares two repositories: refs, HEAD and working tree content.
func assertSame(t *testing.T, a, b string) {
	t.Helper()
	ra, _ := gitx.RefMap(a)
	rb, _ := gitx.RefMap(b)
	if d := gitx.DiffRefs(ra, rb); d != "" {
		t.Fatalf("refs differ: %s", d)
	}
	ha, _ := gitx.Head(a)
	hb, _ := gitx.Head(b)
	if ha != hb {
		t.Fatalf("HEAD differs: %s vs %s", ha, hb)
	}
	cmd := exec.Command("diff", "-r", "--exclude=.git", a, b)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("working trees differ:\n%s", out)
	}
}

func TestBackupRestoreRoundTrip(t *testing.T) {
	home := env(t)
	src := newSource(t, home)
	vaultDir := filepath.Join(home, "vault.git")
	a, out := newApp()

	kit := filepath.Join(home, "kit.txt")
	if err := a.Init(InitOptions{Dir: src, VaultURL: vaultDir, KitOut: kit, Label: "demo"}); err != nil {
		t.Fatalf("init: %v\n%s", err, out)
	}
	if _, err := os.Stat(kit); err != nil {
		t.Fatal("recovery kit not written")
	}

	// generation 1: full
	if err := a.Backup(BackupOptions{Dir: src}); err != nil {
		t.Fatalf("backup 1: %v\n%s", err, out)
	}
	if !strings.Contains(out.String(), "restore proof OK") {
		t.Fatalf("no proof line:\n%s", out)
	}

	// nothing changed: no generation
	out.Reset()
	if err := a.Backup(BackupOptions{Dir: src}); err != nil {
		t.Fatalf("backup noop: %v\n%s", err, out)
	}
	if !strings.Contains(out.String(), "nothing to back up") {
		t.Fatalf("expected noop:\n%s", out)
	}

	// generation 2: incremental with new commits, a deleted branch, a new tag
	commit(t, src, "c.txt", "c\n", "third")
	git(t, src, "branch", "-D", "feature")
	git(t, src, "tag", "v2")
	out.Reset()
	if err := a.Backup(BackupOptions{Dir: src}); err != nil {
		t.Fatalf("backup 2: %v\n%s", err, out)
	}
	if !strings.Contains(out.String(), "generation 000002 pushed: incremental") {
		t.Fatalf("expected incremental:\n%s", out)
	}

	// generation 3: ref-only change (new branch on an existing commit)
	git(t, src, "branch", "again", "v1")
	out.Reset()
	if err := a.Backup(BackupOptions{Dir: src}); err != nil {
		t.Fatalf("backup 3: %v\n%s", err, out)
	}
	if !strings.Contains(out.String(), "generation 000003 pushed") {
		t.Fatalf("expected generation 3:\n%s", out)
	}

	// generation 4: forced full
	commit(t, src, "d.txt", "d\n", "fourth")
	out.Reset()
	if err := a.Backup(BackupOptions{Dir: src, Full: true}); err != nil {
		t.Fatalf("backup 4: %v\n%s", err, out)
	}
	if !strings.Contains(out.String(), "generation 000004 pushed: full") {
		t.Fatalf("expected full:\n%s", out)
	}

	// generation 5: incremental on top of the new full
	commit(t, src, "e.txt", "e\n", "fifth")
	if err := a.Backup(BackupOptions{Dir: src}); err != nil {
		t.Fatalf("backup 5: %v\n%s", err, out)
	}

	// verify from scratch
	out.Reset()
	if err := a.Verify(VerifyOptions{Dir: src}); err != nil {
		t.Fatalf("verify: %v\n%s", err, out)
	}
	if !strings.Contains(out.String(), "source refs match generation 000005") {
		t.Fatalf("verify output:\n%s", out)
	}

	// disaster: the machine is gone. Fresh HOME, only the kit survives.
	home2 := env(t)
	restored := filepath.Join(home2, "restored")
	out.Reset()
	if err := a.Restore(RestoreOptions{VaultURL: vaultDir, To: restored, KitIn: kit}); err != nil {
		t.Fatalf("restore: %v\n%s", err, out)
	}
	assertSame(t, src, restored)

	// an older generation restores the older state (feature branch alive)
	older := filepath.Join(home2, "older")
	if err := a.Restore(RestoreOptions{VaultURL: vaultDir, To: older, Generation: 1}); err != nil {
		t.Fatalf("restore gen 1: %v\n%s", err, out)
	}
	refs, _ := gitx.RefMap(older)
	if _, ok := refs["refs/heads/feature"]; !ok {
		t.Fatalf("generation 1 should still have the feature branch: %v", refs)
	}
	if _, ok := refs["refs/tags/v2"]; ok {
		t.Fatalf("generation 1 must not have tag v2")
	}

	// the restored copy continues the same chain
	commit(t, restored, "g.txt", "g\n", "after restore")
	out.Reset()
	if err := a.Backup(BackupOptions{Dir: restored}); err != nil {
		t.Fatalf("backup from restored: %v\n%s", err, out)
	}
	if !strings.Contains(out.String(), "generation 000006 pushed: incremental") {
		t.Fatalf("expected generation 6 incremental:\n%s", out)
	}
}

func TestStateArchive(t *testing.T) {
	home := env(t)
	src := newSource(t, home)
	vaultDir := filepath.Join(home, "vault.git")
	a, out := newApp()
	if err := a.Init(InitOptions{Dir: src, VaultURL: vaultDir, KitOut: filepath.Join(home, "kit.txt")}); err != nil {
		t.Fatalf("init: %v\n%s", err, out)
	}
	// ignored runtime state next to the repo
	write(t, src, ".gitignore", "data/\nconfig.local\n")
	git(t, src, "add", ".gitignore")
	git(t, src, "commit", "-q", "-m", "ignore")
	write(t, src, "data/ledger.jsonl", "{\"x\":1}\n")
	write(t, src, "data/cache.tmp", "junk")
	write(t, src, "config.local", "secret=1\n")
	cfgPath := filepath.Join(src, ".git", "secretree", "config.json")
	cfg, _ := os.ReadFile(cfgPath)
	patched := strings.Replace(string(cfg), `"state": {}`,
		`"state": {"include": ["data", "config.local"], "exclude": ["*.tmp"], "pre_hook": "mkdir -p \"$SECRETREE_STAGE/data\" && echo snapshot > \"$SECRETREE_STAGE/data/snap.txt\""}`, 1)
	if patched == string(cfg) {
		t.Fatalf("config patch failed:\n%s", cfg)
	}
	if err := os.WriteFile(cfgPath, []byte(patched), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := a.Backup(BackupOptions{Dir: src}); err != nil {
		t.Fatalf("backup: %v\n%s", err, out)
	}
	// unchanged state + unchanged refs = nothing to do
	out.Reset()
	if err := a.Backup(BackupOptions{Dir: src}); err != nil {
		t.Fatalf("backup: %v\n%s", err, out)
	}
	if !strings.Contains(out.String(), "nothing to back up") {
		t.Fatalf("expected noop:\n%s", out)
	}
	// state-only change makes a generation without a bundle
	write(t, src, "data/ledger.jsonl", "{\"x\":1}\n{\"x\":2}\n")
	out.Reset()
	if err := a.Backup(BackupOptions{Dir: src}); err != nil {
		t.Fatalf("backup: %v\n%s", err, out)
	}
	if !strings.Contains(out.String(), "generation 000002 pushed") {
		t.Fatalf("expected generation 2:\n%s", out)
	}

	restored := filepath.Join(home, "restored")
	if err := a.Restore(RestoreOptions{VaultURL: vaultDir, To: restored}); err != nil {
		t.Fatalf("restore: %v\n%s", err, out)
	}
	for name, want := range map[string]string{
		"data/ledger.jsonl": "{\"x\":1}\n{\"x\":2}\n",
		"config.local":      "secret=1\n",
		"data/snap.txt":     "snapshot\n",
	} {
		got, err := os.ReadFile(filepath.Join(restored, name))
		if err != nil || string(got) != want {
			t.Fatalf("%s: got %q err %v", name, got, err)
		}
	}
	if _, err := os.Stat(filepath.Join(restored, "data/cache.tmp")); err == nil {
		t.Fatal("excluded file was archived")
	}
}

func TestTamperDetection(t *testing.T) {
	home := env(t)
	src := newSource(t, home)
	vaultDir := filepath.Join(home, "vault.git")
	a, out := newApp()
	if err := a.Init(InitOptions{Dir: src, VaultURL: vaultDir, KitOut: filepath.Join(home, "kit.txt")}); err != nil {
		t.Fatalf("init: %v\n%s", err, out)
	}
	if err := a.Backup(BackupOptions{Dir: src}); err != nil {
		t.Fatalf("backup: %v\n%s", err, out)
	}
	commit(t, src, "x.txt", "x\n", "more")
	if err := a.Backup(BackupOptions{Dir: src}); err != nil {
		t.Fatalf("backup: %v\n%s", err, out)
	}

	// A hostile host rewrites the vault: replace generation 2's manifest with
	// generation 1's (validly signed, but the chain link no longer matches).
	work := filepath.Join(home, "evil")
	git(t, home, "clone", "-q", vaultDir, work)
	// the attacker controls the host, so the host-side protections are gone
	git(t, vaultDir, "config", "receive.denyNonFastForwards", "false")
	git(t, vaultDir, "config", "receive.denyDeletes", "false")
	repoID := git(t, work, "ls-tree", "--name-only", "HEAD:repos")
	dir := filepath.Join(work, "repos", repoID)
	for _, suffix := range []string{".manifest.age", ".manifest.age.sig"} {
		b, _ := os.ReadFile(filepath.Join(dir, "000001"+suffix))
		if err := os.WriteFile(filepath.Join(dir, "000002"+suffix), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	git(t, work, "commit", "-qam", "tamper")
	git(t, work, "push", "-q", "origin", "HEAD:main")

	out.Reset()
	err := a.Verify(VerifyOptions{Dir: src, Quick: true})
	if err == nil || !strings.Contains(err.Error(), "identity mismatch") && !strings.Contains(err.Error(), "hash chain") {
		t.Fatalf("tampering not detected: err=%v\n%s", err, out)
	}
	// and backup refuses to append to a broken chain
	commit(t, src, "y.txt", "y\n", "again")
	if err := a.Backup(BackupOptions{Dir: src}); err == nil || !strings.Contains(err.Error(), "refusing to append") {
		t.Fatalf("backup should refuse: %v", err)
	}

	// A single flipped byte in a bundle ciphertext is caught by the hash.
	git(t, work, "reset", "-q", "--hard", "HEAD~1")
	bundle := filepath.Join(dir, "000002.bundle.age")
	b, _ := os.ReadFile(bundle)
	b[len(b)/2] ^= 0xff
	if err := os.WriteFile(bundle, b, 0o644); err != nil {
		t.Fatal(err)
	}
	git(t, work, "commit", "-qam", "flip")
	git(t, work, "push", "-qf", "origin", "HEAD:main")
	if err := a.Verify(VerifyOptions{Dir: src}); err == nil || !strings.Contains(err.Error(), "sha256 mismatch") && !strings.Contains(err.Error(), "age:") {
		t.Fatalf("corruption not detected: %v", err)
	}

	// A silently dropped generation breaks contiguity.
	git(t, work, "rm", "-q", "--", filepath.Join("repos", repoID, "000002.manifest.age"), filepath.Join("repos", repoID, "000002.manifest.age.sig"))
	git(t, work, "commit", "-qm", "drop")
	git(t, work, "push", "-qf", "origin", "HEAD:main")
	// (dropping the *last* generation looks like a rollback; the local status still knows about 2)
	_ = vault.GenName
	if err := a.Verify(VerifyOptions{Dir: src, Generation: 2, Quick: false}); err == nil {
		t.Fatal("rollback should fail to produce generation 2")
	}
}

func gitxRunEnv(dir string, env []string, args ...string) (string, error) {
	return gitxRunEnvImpl(dir, env, args...)
}
