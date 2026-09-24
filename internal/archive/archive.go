// Package archive builds and unpacks the out-of-repo state archive:
// a deterministic POSIX tar, zstd-compressed.
package archive

import (
	"archive/tar"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/klauspost/compress/zstd"

	"github.com/buildsnap-dev/secretree/internal/gitx"
)

// Spec says what goes into the archive.
type Spec struct {
	Root    string   // work tree root; Include paths are relative to it
	Include []string // files or directories
	Exclude []string // glob patterns (filepath.Match) against relative paths
	PreHook string   // shell command run with $SECRETREE_STAGE; its output dir is archived too
}

// Build writes the archive to out. It returns false if there was nothing
// to archive. The result is deterministic for unchanged inputs so the
// caller can compare hashes across runs.
func Build(spec Spec, out string, stage string) (bool, error) {
	var entries []entry
	if spec.PreHook != "" {
		if err := os.MkdirAll(stage, 0o700); err != nil {
			return false, err
		}
		cmd := gitx.ShellCommand(spec.PreHook)
		cmd.Dir = spec.Root
		cmd.Env = append(os.Environ(), "SECRETREE_STAGE="+stage)
		cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
		if err := cmd.Run(); err != nil {
			return false, fmt.Errorf("state.pre_hook failed: %w", err)
		}
		es, err := collect(stage, ".", nil)
		if err != nil {
			return false, err
		}
		for i := range es {
			es[i].staged = true
		}
		entries = append(entries, es...)
	}
	for _, inc := range spec.Include {
		es, err := collect(spec.Root, inc, spec.Exclude)
		if err != nil {
			return false, err
		}
		entries = append(entries, es...)
	}
	if len(entries) == 0 {
		return false, nil
	}
	// staged copies win over work-tree copies of the same path
	seen := map[string]bool{}
	var uniq []entry
	for _, e := range entries {
		if !seen[e.rel] {
			seen[e.rel] = true
			uniq = append(uniq, e)
		}
	}
	sort.Slice(uniq, func(i, j int) bool { return uniq[i].rel < uniq[j].rel })

	f, err := os.OpenFile(out, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return false, err
	}
	defer f.Close()
	zw, err := zstd.NewWriter(f, zstd.WithEncoderLevel(zstd.SpeedDefault))
	if err != nil {
		return false, err
	}
	tw := tar.NewWriter(zw)
	for _, e := range uniq {
		if err := addFile(tw, e); err != nil {
			return false, err
		}
	}
	if err := tw.Close(); err != nil {
		return false, err
	}
	if err := zw.Close(); err != nil {
		return false, err
	}
	return true, f.Close()
}

type entry struct {
	rel    string // path inside the archive, slash separated
	abs    string
	staged bool // produced by the pre-hook: its mtime is noise, not signal
}

func collect(root, rel string, exclude []string) ([]entry, error) {
	abs := filepath.Join(root, rel)
	info, err := os.Lstat(abs)
	if os.IsNotExist(err) {
		return nil, nil // configured but absent: fine
	}
	if err != nil {
		return nil, err
	}
	var out []entry
	if !info.IsDir() {
		if info.Mode().IsRegular() && !excluded(filepath.ToSlash(rel), exclude) {
			out = append(out, entry{rel: filepath.ToSlash(filepath.Clean(rel)), abs: abs})
		}
		return out, nil
	}
	err = filepath.WalkDir(abs, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.Type().IsRegular() {
			return nil
		}
		r, _ := filepath.Rel(root, p)
		r = filepath.ToSlash(r)
		if excluded(r, exclude) {
			return nil
		}
		out = append(out, entry{rel: r, abs: p})
		return nil
	})
	return out, err
}

func excluded(rel string, patterns []string) bool {
	for _, pat := range patterns {
		if ok, _ := filepath.Match(pat, rel); ok {
			return true
		}
		if ok, _ := filepath.Match(pat, filepath.Base(rel)); ok {
			return true
		}
		if strings.HasPrefix(rel, strings.TrimSuffix(pat, "/")+"/") {
			return true
		}
	}
	return false
}

func addFile(tw *tar.Writer, e entry) error {
	info, err := os.Stat(e.abs)
	if err != nil {
		return err
	}
	mtime := info.ModTime().Truncate(1e9)
	if e.staged {
		// hook output is regenerated every run; a stable mtime keeps the
		// archive byte-identical when the content is identical
		mtime = time.Unix(0, 0)
	}
	hdr := &tar.Header{
		Typeflag: tar.TypeReg,
		Name:     e.rel,
		Mode:     int64(info.Mode().Perm()),
		Size:     info.Size(),
		ModTime:  mtime,
		Format:   tar.FormatPAX,
	}
	if err := tw.WriteHeader(hdr); err != nil {
		return err
	}
	f, err := os.Open(e.abs)
	if err != nil {
		return err
	}
	defer f.Close()
	n, err := io.CopyN(tw, f, info.Size())
	if err != nil {
		return fmt.Errorf("%s: %w (file changed while archiving?)", e.rel, err)
	}
	if n != info.Size() {
		return fmt.Errorf("%s: short read", e.rel)
	}
	return nil
}

// Unpack extracts an archive into dir. encoding is "zstd" or "none".
func Unpack(archive, encoding, dir string) (int, error) {
	f, err := os.Open(archive)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	var r io.Reader = f
	if encoding == "zstd" {
		zr, err := zstd.NewReader(f)
		if err != nil {
			return 0, err
		}
		defer zr.Close()
		r = zr
	}
	tr := tar.NewReader(r)
	count := 0
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return count, nil
		}
		if err != nil {
			return count, err
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		rel := filepath.Clean(filepath.FromSlash(hdr.Name))
		if filepath.IsAbs(rel) || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return count, fmt.Errorf("archive: refusing path %q", hdr.Name)
		}
		dst := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return count, err
		}
		out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.FileMode(hdr.Mode)&0o777)
		if err != nil {
			return count, err
		}
		if _, err := io.Copy(out, tr); err != nil {
			out.Close()
			return count, err
		}
		if err := out.Close(); err != nil {
			return count, err
		}
		_ = os.Chtimes(dst, hdr.ModTime, hdr.ModTime)
		count++
	}
}
