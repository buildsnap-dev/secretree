// Package crypt wraps age encryption and OpenSSH signatures. It contains no
// cryptography of its own, only plumbing: streaming, hashing, framing.
package crypt

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"

	"filippo.io/age"
	"github.com/hiddeco/sshsig"
	"golang.org/x/crypto/ssh"

	"github.com/buildsnap-dev/secretree/internal/keys"
)

// Digest describes one encrypted file.
type Digest struct {
	PlaintextSHA256  string
	CiphertextSHA256 string
	Size             int64 // ciphertext bytes
}

// ParseRecipients parses age public keys.
func ParseRecipients(strs []string) ([]age.Recipient, error) {
	var rs []age.Recipient
	for _, s := range strs {
		r, err := age.ParseX25519Recipient(s)
		if err != nil {
			return nil, fmt.Errorf("recipient %q: %w", s, err)
		}
		rs = append(rs, r)
	}
	if len(rs) == 0 {
		return nil, errors.New("no recipients")
	}
	return rs, nil
}

// EncryptStream encrypts src to dst for the recipients, hashing both sides.
func EncryptStream(dst io.Writer, src io.Reader, recipients []age.Recipient) (Digest, error) {
	ptHash := sha256.New()
	ctHash := sha256.New()
	counter := &countWriter{}
	w, err := age.Encrypt(io.MultiWriter(dst, ctHash, counter), recipients...)
	if err != nil {
		return Digest{}, err
	}
	if _, err := io.Copy(io.MultiWriter(w, ptHash), src); err != nil {
		return Digest{}, err
	}
	if err := w.Close(); err != nil {
		return Digest{}, err
	}
	return Digest{
		PlaintextSHA256:  hex.EncodeToString(ptHash.Sum(nil)),
		CiphertextSHA256: hex.EncodeToString(ctHash.Sum(nil)),
		Size:             counter.n,
	}, nil
}

// EncryptFile encrypts srcPath into dstPath.
func EncryptFile(dstPath, srcPath string, recipients []age.Recipient) (Digest, error) {
	in, err := os.Open(srcPath)
	if err != nil {
		return Digest{}, err
	}
	defer in.Close()
	out, err := os.OpenFile(dstPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return Digest{}, err
	}
	d, err := EncryptStream(out, in, recipients)
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	return d, err
}

// EncryptBytes encrypts a small in-memory plaintext.
func EncryptBytes(plain []byte, recipients []age.Recipient) ([]byte, Digest, error) {
	var buf bytes.Buffer
	d, err := EncryptStream(&buf, bytes.NewReader(plain), recipients)
	return buf.Bytes(), d, err
}

// DecryptStream decrypts src into dst and checks the expected digests. An
// empty expected field skips that check. The ciphertext hash is computed
// over exactly the bytes read, so a truncated input fails loudly.
func DecryptStream(dst io.Writer, src io.Reader, identity age.Identity, expect Digest) error {
	ctHash := sha256.New()
	tee := io.TeeReader(src, ctHash)
	r, err := age.Decrypt(tee, identity)
	if err != nil {
		return fmt.Errorf("age: %w", err)
	}
	ptHash := sha256.New()
	if _, err := io.Copy(io.MultiWriter(dst, ptHash), r); err != nil {
		return fmt.Errorf("age: %w", err)
	}
	// drain anything after the age payload so the ciphertext hash is total
	if _, err := io.Copy(io.Discard, tee); err != nil {
		return err
	}
	if got := hex.EncodeToString(ctHash.Sum(nil)); expect.CiphertextSHA256 != "" && got != expect.CiphertextSHA256 {
		return fmt.Errorf("ciphertext sha256 mismatch: got %s want %s", got, expect.CiphertextSHA256)
	}
	if got := hex.EncodeToString(ptHash.Sum(nil)); expect.PlaintextSHA256 != "" && got != expect.PlaintextSHA256 {
		return fmt.Errorf("plaintext sha256 mismatch: got %s want %s", got, expect.PlaintextSHA256)
	}
	return nil
}

// DecryptFile decrypts srcPath into dstPath with digest checks.
func DecryptFile(dstPath, srcPath string, identity age.Identity, expect Digest) error {
	in, err := os.Open(srcPath)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dstPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	err = DecryptStream(out, in, identity, expect)
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	return err
}

// DecryptBytes decrypts a small ciphertext held in memory.
func DecryptBytes(cipher []byte, identity age.Identity) ([]byte, error) {
	var buf bytes.Buffer
	if err := DecryptStream(&buf, bytes.NewReader(cipher), identity, Digest{}); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// SHA256File hashes a file on disk.
func SHA256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// SHA256Bytes hashes a byte slice.
func SHA256Bytes(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// Sign produces an armored SSHSIG signature over data in the secretree namespace.
func Sign(data []byte, signer ssh.Signer) ([]byte, error) {
	sig, err := sshsig.Sign(bytes.NewReader(data), signer, sshsig.HashSHA256, keys.Namespace)
	if err != nil {
		return nil, err
	}
	return sshsig.Armor(sig), nil
}

// Verify checks an armored signature over data against the allowed signers.
// It returns the public key that verified.
func Verify(data, armored []byte, allowed []ssh.PublicKey) (ssh.PublicKey, error) {
	sig, err := sshsig.Unarmor(armored)
	if err != nil {
		return nil, fmt.Errorf("signature: %w", err)
	}
	if sig.Namespace != keys.Namespace {
		return nil, fmt.Errorf("signature: namespace %q, want %q", sig.Namespace, keys.Namespace)
	}
	for _, pub := range allowed {
		if !bytes.Equal(pub.Marshal(), sig.PublicKey.Marshal()) {
			continue
		}
		if err := sshsig.Verify(bytes.NewReader(data), sig, pub, sshsig.HashSHA256, keys.Namespace); err != nil {
			return nil, fmt.Errorf("signature: %w", err)
		}
		return pub, nil
	}
	return nil, fmt.Errorf("signature: signer %s is not in allowed_signers", ssh.FingerprintSHA256(sig.PublicKey))
}

type countWriter struct{ n int64 }

func (c *countWriter) Write(p []byte) (int, error) { c.n += int64(len(p)); return len(p), nil }
