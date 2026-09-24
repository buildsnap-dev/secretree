package app

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/buildsnap-dev/secretree/internal/crypt"
	"github.com/buildsnap-dev/secretree/internal/gitx"
	"github.com/buildsnap-dev/secretree/internal/keys"
	"github.com/buildsnap-dev/secretree/internal/vault"
)

// Join requests can travel through the vault itself: the joiner encrypts
// its public keys to the current recipients (they are in vault.json, which
// is plaintext) and pushes them to requests/<id>.json.age. Any member then
// sees them with `member pending` and approves with `member approve`.
// No file needs to be mailed; the host sees only a random file name.

const requestsDir = "requests"

type joinRequest struct {
	Format    string    `json:"format"`
	VaultID   string    `json:"vault_id"`
	Name      string    `json:"name"`
	Recipient string    `json:"recipient"`
	Signer    string    `json:"signer"`
	Created   time.Time `json:"created"`
}

// pushJoinRequest writes the request into the vault. cacheDir is a synced
// clone; the joiner needs push access to the host, nothing more.
func (a *App) pushJoinRequest(cacheDir, branch string, kb *keys.Bundle, meta *vault.Meta, name string) (string, error) {
	rec, err := kb.Recipient()
	if err != nil {
		return "", err
	}
	line, err := kb.AllowedSignersLine(name)
	if err != nil {
		return "", err
	}
	req := joinRequest{Format: "secretree-join/1", VaultID: kb.VaultID, Name: name, Recipient: rec, Signer: line, Created: time.Now().UTC().Truncate(time.Second)}
	plain, err := json.MarshalIndent(&req, "", "  ")
	if err != nil {
		return "", err
	}
	recipients, err := crypt.ParseRecipients(meta.Recipients)
	if err != nil {
		return "", err
	}
	cipher, _, err := crypt.EncryptBytes(plain, recipients)
	if err != nil {
		return "", err
	}
	id, err := keys.NewVaultID()
	if err != nil {
		return "", err
	}
	rel := path.Join(requestsDir, id+".json.age")
	if err := os.MkdirAll(filepath.Join(cacheDir, requestsDir), 0o700); err != nil {
		return "", err
	}
	if err := os.WriteFile(filepath.Join(cacheDir, rel), cipher, 0o600); err != nil {
		return "", err
	}
	if err := commitPush(cacheDir, branch, []string{rel}); err != nil {
		return "", err
	}
	return id, nil
}

type pendingRequest struct {
	ID  string
	Req joinRequest
}

// pendingRequests lists requests this key can decrypt.
func (a *App) pendingRequests(r *repo, vs *vaultState) ([]pendingRequest, error) {
	if !vs.Reader.Exists(requestsDir) {
		return nil, nil
	}
	out, err := gitx.Run(vs.Reader.Dir, "ls-tree", "--name-only", "HEAD:"+requestsDir)
	if err != nil {
		return nil, err
	}
	var list []pendingRequest
	for _, name := range strings.Fields(out) {
		if !strings.HasSuffix(name, ".json.age") {
			continue
		}
		cipher, err := vs.Reader.ReadFile(path.Join(requestsDir, name))
		if err != nil {
			continue
		}
		plain, err := crypt.DecryptBytes(cipher, r.identity)
		if err != nil {
			continue // encrypted to an earlier recipient set, or garbage
		}
		var req joinRequest
		if err := json.Unmarshal(plain, &req); err != nil || req.VaultID != vs.Meta.VaultID {
			continue
		}
		list = append(list, pendingRequest{ID: strings.TrimSuffix(name, ".json.age"), Req: req})
	}
	return list, nil
}

// MemberPending prints join requests waiting in the vault.
func (a *App) MemberPending(dir string) error {
	r, err := a.openRepo(dir)
	if err != nil {
		return err
	}
	vs, err := a.loadVault(r)
	if err != nil {
		return err
	}
	list, err := a.pendingRequests(r, vs)
	if err != nil {
		return err
	}
	if len(list) == 0 {
		a.logf("no pending join requests")
		return nil
	}
	for _, p := range list {
		a.logf("  %-16s %s  requested %s  (id %s)", p.Req.Name, p.Req.Recipient, p.Req.Created.Format("2006-01-02 15:04"), p.ID[:8])
	}
	a.logf("approve with: secretree member approve <name> [--role agent]")
	return nil
}

// MemberApprove adds a pending request as a member and removes it from the vault.
func (a *App) MemberApprove(dir, nameOrID, role string) error {
	r, err := a.openRepo(dir)
	if err != nil {
		return err
	}
	vs, err := a.loadVault(r)
	if err != nil {
		return err
	}
	list, err := a.pendingRequests(r, vs)
	if err != nil {
		return err
	}
	var hit *pendingRequest
	for i := range list {
		if list[i].Req.Name == nameOrID || strings.HasPrefix(list[i].ID, nameOrID) {
			if hit != nil {
				return fmt.Errorf("ambiguous: several requests match %q; use the id", nameOrID)
			}
			hit = &list[i]
		}
	}
	if hit == nil {
		return fmt.Errorf("no pending request named %q (secretree member pending)", nameOrID)
	}
	if err := a.MemberAdd(MemberOptions{Dir: dir, Recipient: hit.Req.Recipient, Signer: hit.Req.Signer, Name: hit.Req.Name, Role: role}); err != nil {
		return err
	}
	// remove the request file (a fresh sync: MemberAdd pushed)
	vs2, err := a.loadVault(r)
	if err != nil {
		return err
	}
	rel := path.Join(requestsDir, hit.ID+".json.age")
	if _, err := gitx.Run(r.Paths.Cache, "rm", "-q", "--cached", "--", rel); err != nil {
		return err
	}
	if _, err := gitx.Run(r.Paths.Cache, "-c", "user.name=secretree", "-c", "user.email=secretree@localhost", "commit", "--quiet", "--no-verify", "-m", "backup"); err != nil {
		return err
	}
	if _, err := gitx.Run(r.Paths.Cache, "push", "--quiet", "origin", "HEAD:refs/heads/"+vs2.Branch); err != nil {
		return fmt.Errorf("push to vault: %w", err)
	}
	a.logf("request %s removed from the vault; %s can now clone", hit.ID[:8], hit.Req.Name)
	return nil
}

// MemberDeny removes a pending request without adding the member.
func (a *App) MemberDeny(dir, nameOrID string) error {
	r, err := a.openRepo(dir)
	if err != nil {
		return err
	}
	vs, err := a.loadVault(r)
	if err != nil {
		return err
	}
	list, err := a.pendingRequests(r, vs)
	if err != nil {
		return err
	}
	for _, p := range list {
		if p.Req.Name == nameOrID || strings.HasPrefix(p.ID, nameOrID) {
			rel := path.Join(requestsDir, p.ID+".json.age")
			if _, err := gitx.Run(r.Paths.Cache, "rm", "-q", "--cached", "--", rel); err != nil {
				return err
			}
			if _, err := gitx.Run(r.Paths.Cache, "-c", "user.name=secretree", "-c", "user.email=secretree@localhost", "commit", "--quiet", "--no-verify", "-m", "backup"); err != nil {
				return err
			}
			if _, err := gitx.Run(r.Paths.Cache, "push", "--quiet", "origin", "HEAD:refs/heads/"+vs.Branch); err != nil {
				return fmt.Errorf("push to vault: %w", err)
			}
			a.logf("request from %s denied and removed", p.Req.Name)
			return nil
		}
	}
	return errors.New("no such pending request")
}
