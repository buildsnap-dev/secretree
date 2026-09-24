// Package keystore stores key bundles in the OS key store.
//
// macOS: the login Keychain via the `security` CLI (service "secretree").
// Linux: the Secret Service (GNOME Keyring, KDE Wallet) via `secret-tool`
// when it is installed. Elsewhere, and whenever SECRETREE_KEYSTORE=file: a
// 0600 JSON file under $SECRETREE_HOME (default ~/.config/secretree). The
// file store is also what tests use so they never touch a real key store.
package keystore

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/buildsnap-dev/secretree/internal/keys"
)

// ErrNotFound is returned when no bundle exists for a vault id.
var ErrNotFound = errors.New("no keys for this vault in the key store")

// Store persists key bundles.
type Store interface {
	Get(vaultID string) (*keys.Bundle, error)
	Put(b *keys.Bundle) error
	Delete(vaultID string) error
	// Describe names the backend for status output.
	Describe() string
}

// Open picks the backend from the environment and platform.
func Open() (Store, error) {
	switch os.Getenv("SECRETREE_KEYSTORE") {
	case "file":
		return newFileStore()
	case "keychain":
		return keychainStore{}, nil
	case "secret-service":
		return secretServiceStore{}, nil
	case "":
		if runtime.GOOS == "darwin" {
			return keychainStore{}, nil
		}
		if runtime.GOOS == "linux" {
			if _, err := exec.LookPath("secret-tool"); err == nil {
				return secretServiceStore{}, nil
			}
		}
		return newFileStore()
	default:
		return nil, fmt.Errorf("SECRETREE_KEYSTORE: unknown backend %q", os.Getenv("SECRETREE_KEYSTORE"))
	}
}

// Home returns the secretree config directory ($SECRETREE_HOME or ~/.config/secretree).
func Home() (string, error) {
	if h := os.Getenv("SECRETREE_HOME"); h != "" {
		return h, nil
	}
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "secretree"), nil
}

// ---- file store ----

type fileStore struct{ dir string }

func newFileStore() (Store, error) {
	home, err := Home()
	if err != nil {
		return nil, err
	}
	dir := filepath.Join(home, "keys")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	return fileStore{dir: dir}, nil
}

func (f fileStore) path(id string) string { return filepath.Join(f.dir, id+".json") }

func (f fileStore) Get(vaultID string) (*keys.Bundle, error) {
	data, err := os.ReadFile(f.path(vaultID))
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	var b keys.Bundle
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, err
	}
	return &b, nil
}

func (f fileStore) Put(b *keys.Bundle) error {
	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(f.path(b.VaultID), data, 0o600)
}

func (f fileStore) Delete(vaultID string) error {
	err := os.Remove(f.path(vaultID))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

func (f fileStore) Describe() string { return "file (" + f.dir + ")" }

// ---- macOS Keychain ----

type keychainStore struct{}

const service = "secretree"

func account(vaultID, role string) string { return vaultID + "/" + role }

func (keychainStore) Get(vaultID string) (*keys.Bundle, error) {
	ageID, err := keychainGet(account(vaultID, "age-identity"))
	if err != nil {
		return nil, err
	}
	sigB64, err := keychainGet(account(vaultID, "signing-key"))
	if err != nil {
		return nil, err
	}
	pem, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return nil, fmt.Errorf("keychain: signing key not base64: %w", err)
	}
	return &keys.Bundle{VaultID: vaultID, AgeIdentity: ageID, SigningKeyPEM: string(pem)}, nil
}

func (keychainStore) Put(b *keys.Bundle) error {
	if err := keychainPut(account(b.VaultID, "age-identity"), strings.TrimSpace(b.AgeIdentity)); err != nil {
		return err
	}
	return keychainPut(account(b.VaultID, "signing-key"), base64.StdEncoding.EncodeToString([]byte(b.SigningKeyPEM)))
}

func (keychainStore) Delete(vaultID string) error {
	for _, role := range []string{"age-identity", "signing-key"} {
		cmd := exec.Command("security", "delete-generic-password", "-s", service, "-a", account(vaultID, role))
		_ = cmd.Run()
	}
	return nil
}

func (keychainStore) Describe() string { return "macOS Keychain (service secretree)" }

func keychainGet(acct string) (string, error) {
	cmd := exec.Command("security", "find-generic-password", "-s", service, "-a", acct, "-w")
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		if strings.Contains(errb.String(), "could not be found") {
			return "", ErrNotFound
		}
		return "", fmt.Errorf("keychain read failed: %s", strings.TrimSpace(errb.String()))
	}
	return strings.TrimSpace(out.String()), nil
}

func keychainPut(acct, secret string) error {
	// `security -i` reads its command line from stdin, so the secret never
	// appears in argv (visible to every process via ps). -U updates in place.
	if strings.ContainsAny(secret, "'\n") {
		return errors.New("keychain: secret contains characters the security tool cannot quote")
	}
	cmd := exec.Command("security", "-i")
	cmd.Stdin = strings.NewReader(fmt.Sprintf("add-generic-password -U -s %s -a '%s' -l 'secretree %s' -j 'secretree vault key; do not delete' -w '%s'\n",
		service, acct, acct, secret))
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil || strings.Contains(out.String()+errb.String(), "rror") {
		return fmt.Errorf("keychain write failed: %s", strings.TrimSpace(out.String()+errb.String()))
	}
	return nil
}

// ---- Linux Secret Service (libsecret's secret-tool) ----

type secretServiceStore struct{}

func (secretServiceStore) Get(vaultID string) (*keys.Bundle, error) {
	ageID, err := secretToolGet(account(vaultID, "age-identity"))
	if err != nil {
		return nil, err
	}
	sigB64, err := secretToolGet(account(vaultID, "signing-key"))
	if err != nil {
		return nil, err
	}
	pem, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return nil, fmt.Errorf("secret service: signing key not base64: %w", err)
	}
	return &keys.Bundle{VaultID: vaultID, AgeIdentity: ageID, SigningKeyPEM: string(pem)}, nil
}

func (secretServiceStore) Put(b *keys.Bundle) error {
	if err := secretToolPut(account(b.VaultID, "age-identity"), strings.TrimSpace(b.AgeIdentity)); err != nil {
		return err
	}
	return secretToolPut(account(b.VaultID, "signing-key"), base64.StdEncoding.EncodeToString([]byte(b.SigningKeyPEM)))
}

func (secretServiceStore) Delete(vaultID string) error {
	for _, role := range []string{"age-identity", "signing-key"} {
		_ = exec.Command("secret-tool", "clear", "service", service, "account", account(vaultID, role)).Run()
	}
	return nil
}

func (secretServiceStore) Describe() string { return "Secret Service (secret-tool, service secretree)" }

func secretToolGet(acct string) (string, error) {
	cmd := exec.Command("secret-tool", "lookup", "service", service, "account", acct)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil || out.Len() == 0 {
		if errb.Len() == 0 {
			return "", ErrNotFound
		}
		return "", fmt.Errorf("secret service read failed: %s", strings.TrimSpace(errb.String()))
	}
	return strings.TrimSpace(out.String()), nil
}

func secretToolPut(acct, secret string) error {
	// the secret goes in on stdin
	cmd := exec.Command("secret-tool", "store", "--label=secretree "+acct, "service", service, "account", acct)
	cmd.Stdin = strings.NewReader(secret)
	var errb bytes.Buffer
	cmd.Stderr = &errb
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("secret service write failed: %s", strings.TrimSpace(errb.String()))
	}
	return nil
}
