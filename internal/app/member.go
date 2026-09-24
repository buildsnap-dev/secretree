package app

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/buildsnap-dev/secretree/internal/config"
	"github.com/buildsnap-dev/secretree/internal/crypt"
	"github.com/buildsnap-dev/secretree/internal/gitx"
	"github.com/buildsnap-dev/secretree/internal/keys"
	"github.com/buildsnap-dev/secretree/internal/keystore"
	"github.com/buildsnap-dev/secretree/internal/vault"
)

// JoinOptions configures Join.
type JoinOptions struct {
	VaultURL string
	Name     string // device/person name shown to admins
	Out      string // write the join request here ("" = stdout)
	NoPush   bool   // do not push the request into the vault; print/write it instead
}

// Join prepares a new device: fresh keys for the vault in the key store,
// and a join request an existing member approves with `member add`.
func (a *App) Join(o JoinOptions) error {
	if o.VaultURL == "" {
		return errors.New("--vault is required")
	}
	url, err := ensureRemote(o.VaultURL)
	if err != nil {
		return err
	}
	tmp, err := os.MkdirTemp("", "secretree-join-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	dir := filepath.Join(tmp, "vault")
	if err := cloneVault(url, dir); err != nil {
		return err
	}
	reader := &vault.Reader{Dir: dir}
	raw, err := reader.ReadFile(vault.MetaFile)
	if err != nil {
		return fmt.Errorf("not a secretree vault (no %s)", vault.MetaFile)
	}
	var m vault.Meta
	if err := json.Unmarshal(raw, &m); err != nil {
		return err
	}
	store, err := keystore.Open()
	if err != nil {
		return err
	}
	kb, err := store.Get(m.VaultID)
	if err == nil {
		fp, _ := kb.Fingerprint()
		return fmt.Errorf("this device already holds keys for vault %s (signer %s); print its join request with `secretree member request`", m.VaultID, fp)
	} else if !errors.Is(err, keystore.ErrNotFound) {
		return err
	}
	kb, err = keys.Generate(m.VaultID)
	if err != nil {
		return err
	}
	if err := store.Put(kb); err != nil {
		return err
	}
	name := o.Name
	if name == "" {
		name, _ = os.Hostname()
	}
	req, err := joinRequestText(kb, name)
	if err != nil {
		return err
	}
	if !o.NoPush {
		// the request travels through the vault: encrypted to the current
		// members, pushed as requests/<id>.json.age
		cache := filepath.Join(tmp, "cache")
		if branch, _, err := syncCache(url, cache, ""); err == nil {
			if id, err := a.pushJoinRequest(cache, branch, kb, &m, name); err == nil {
				a.logf("keys stored in %s.", store.Describe())
				a.logf("join request %s pushed to the vault; a member approves it with:\n  secretree member approve %s", id[:8], name)
				a.logf("then clone with: secretree clone %s", o.VaultURL)
				return nil
			} else {
				a.logf("could not push the request to the vault (%v); falling back to a file", err)
			}
		}
	}
	if o.Out != "" {
		if err := os.WriteFile(o.Out, []byte(req), 0o644); err != nil {
			return err
		}
		a.logf("keys stored in %s; join request written to %s", store.Describe(), o.Out)
	} else {
		a.logf("keys stored in %s. Send this join request to a current member:\n", store.Describe())
		fmt.Fprint(a.Out, req)
	}
	a.logf("\nOnce they run `secretree member add --request <file>`, clone with: secretree clone %s", o.VaultURL)
	return nil
}

func joinRequestText(kb *keys.Bundle, name string) (string, error) {
	rec, err := kb.Recipient()
	if err != nil {
		return "", err
	}
	line, err := kb.AllowedSignersLine(name)
	if err != nil {
		return "", err
	}
	fp, _ := kb.Fingerprint()
	return fmt.Sprintf("secretree join request\nvault: %s\nname: %s\nrecipient: %s\nsigner: %s\nfingerprint: %s\n", kb.VaultID, name, rec, line, fp), nil
}

// MemberRequest prints this device's join request (for an already-generated key).
func (a *App) MemberRequest(dir string) error {
	r, err := a.openRepo(dir)
	if err != nil {
		return err
	}
	req, err := joinRequestText(r.Keys, r.Cfg.Label)
	if err != nil {
		return err
	}
	fmt.Fprint(a.Out, req)
	return nil
}

// MemberOptions configures MemberAdd / MemberRemove.
type MemberOptions struct {
	Dir       string
	Request   string // join request file
	Recipient string
	Signer    string // ssh public key line ("ssh-ed25519 AAAA... comment")
	Name      string
	Role      string // "" or "agent": agents may read, comment and review, but their approvals do not count and they cannot merge
}

// MemberAdd adds a recipient and signer to the vault, re-signs vault.json,
// and writes a full generation to the new recipient set so the newcomer
// can read from now on. Earlier generations stay unreadable to them.
func (a *App) MemberAdd(o MemberOptions) error {
	if o.Request != "" {
		text, err := os.ReadFile(o.Request)
		if err != nil {
			return err
		}
		for _, line := range strings.Split(string(text), "\n") {
			k, v, ok := strings.Cut(line, ": ")
			if !ok {
				continue
			}
			switch strings.TrimSpace(k) {
			case "recipient":
				o.Recipient = strings.TrimSpace(v)
			case "signer":
				o.Signer = strings.TrimSpace(v)
			case "name":
				if o.Name == "" {
					o.Name = strings.TrimSpace(v)
				}
			}
		}
	}
	if o.Recipient == "" {
		return errors.New("--recipient (age1...) or --request <file> is required")
	}
	if _, err := crypt.ParseRecipients([]string{o.Recipient}); err != nil {
		return err
	}
	r, err := a.openRepo(o.Dir)
	if err != nil {
		return err
	}
	unlock, err := r.lock()
	if err != nil {
		return err
	}
	defer unlock()
	vs, err := a.loadVault(r)
	if err != nil {
		return err
	}
	meta := vs.Meta
	for _, rec := range meta.Recipients {
		if rec == o.Recipient {
			return errors.New("that recipient is already a member")
		}
	}
	meta.Recipients = append(meta.Recipients, o.Recipient)
	if o.Role != "" && o.Role != "agent" {
		return fmt.Errorf("--role must be empty or \"agent\"")
	}
	member := vault.Member{Name: o.Name, Role: o.Role, Recipient: o.Recipient, Added: time.Now().UTC().Truncate(time.Second)}
	if o.Signer != "" {
		line := o.Signer
		if !strings.HasPrefix(line, keys.Principal+" ") {
			pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
			if err != nil {
				return fmt.Errorf("--signer: %w", err)
			}
			line = keys.AllowedSignersLine(pub, o.Name)
		}
		pubs, err := keys.ParseAllowedSigners([]string{line})
		if err != nil {
			return err
		}
		member.SignerFingerprint = ssh.FingerprintSHA256(pubs[0])
		meta.AllowedSigners = append(meta.AllowedSigners, line)
	}
	meta.Members = append(meta.Members, member)
	if err := a.writeMeta(r, vs, meta); err != nil {
		return err
	}
	if o.Role == "agent" {
		a.logf("agent added: %s (%s); its approvals do not count and it cannot merge", o.Name, o.Recipient)
	} else {
		a.logf("member added: %s (%s)", o.Name, o.Recipient)
	}
	return a.reencryptForward(r, vs)
}

// MemberRemove removes a recipient (and its signer) and writes a full
// generation to the remaining set. What they already fetched stays theirs.
func (a *App) MemberRemove(o MemberOptions) error {
	r, err := a.openRepo(o.Dir)
	if err != nil {
		return err
	}
	unlock, err := r.lock()
	if err != nil {
		return err
	}
	defer unlock()
	vs, err := a.loadVault(r)
	if err != nil {
		return err
	}
	meta := vs.Meta
	ours, _ := r.Keys.Recipient()
	target := o.Recipient
	if target == "" && o.Name != "" {
		for _, m := range meta.Members {
			if m.Name == o.Name {
				target = m.Recipient
			}
		}
	}
	if target == "" {
		return errors.New("--recipient or --name is required")
	}
	if target == ours {
		return errors.New("refusing to remove this device's own key")
	}
	var recips []string
	found := false
	for _, rec := range meta.Recipients {
		if rec == target {
			found = true
			continue
		}
		recips = append(recips, rec)
	}
	if !found {
		return fmt.Errorf("recipient %s is not a member", target)
	}
	meta.Recipients = recips
	var members []vault.Member
	removedFP := ""
	for _, m := range meta.Members {
		if m.Recipient == target {
			removedFP = m.SignerFingerprint
			continue
		}
		members = append(members, m)
	}
	meta.Members = members
	if removedFP != "" {
		lastGen := 0
		if vs.Chain.Last() != nil {
			lastGen = vs.Chain.Last().Num
		}
		ledgerCount := 0
		if seqs, err := ledgerSeqs(vs.Reader, r.Cfg.RepoID); err == nil && len(seqs) > 0 {
			ledgerCount = seqs[len(seqs)-1]
		}
		var signers []string
		for _, line := range meta.AllowedSigners {
			pubs, err := keys.ParseAllowedSigners([]string{line})
			if err == nil && ssh.FingerprintSHA256(pubs[0]) == removedFP {
				meta.RevokedSigners = append(meta.RevokedSigners, vault.RevokedSigner{
					Line: line, Fingerprint: removedFP, RevokedAt: time.Now().UTC().Truncate(time.Second),
					LastGeneration: lastGen, LastLedger: ledgerCount,
				})
				continue
			}
			signers = append(signers, line)
		}
		meta.AllowedSigners = signers
	}
	if err := a.writeMeta(r, vs, meta); err != nil {
		return err
	}
	a.logf("member removed: %s", target)
	return a.reencryptForward(r, vs)
}

// MemberList prints recipients and signers.
func (a *App) MemberList(dir string) error {
	r, err := a.openRepo(dir)
	if err != nil {
		return err
	}
	vs, err := a.loadVault(r)
	if err != nil {
		return err
	}
	ours, _ := r.Keys.Recipient()
	ourFP, _ := r.Keys.Fingerprint()
	a.logf("vault %s: %d recipient(s), %d signer(s)", vs.Meta.VaultID, len(vs.Meta.Recipients), len(vs.Signers.Active))
	named := map[string]vault.Member{}
	for _, m := range vs.Meta.Members {
		named[m.Recipient] = m
	}
	for _, rec := range vs.Meta.Recipients {
		mark := ""
		if rec == ours {
			mark = "  (this device)"
		}
		m := named[rec]
		name := m.Name
		if name == "" {
			name = "-"
		}
		if m.Role == "agent" {
			mark += "  [agent]"
		}
		a.logf("  %-16s %s  signer %s%s", name, rec, orDash(m.SignerFingerprint), mark)
	}
	for _, s := range vs.Signers.Active {
		fp := ssh.FingerprintSHA256(s)
		known := false
		for _, m := range vs.Meta.Members {
			if m.SignerFingerprint == fp {
				known = true
			}
		}
		if !known {
			mark := ""
			if fp == ourFP {
				mark = "  (this device)"
			}
			a.logf("  %-16s signer-only %s%s", "-", fp, mark)
		}
	}
	return nil
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// writeMeta signs and pushes a new vault.json.
func (a *App) writeMeta(r *repo, vs *vaultState, meta *vault.Meta) error {
	data, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	sig, err := crypt.Sign(data, r.signer)
	if err != nil {
		return err
	}
	dir := r.Paths.Cache
	if err := os.WriteFile(filepath.Join(dir, vault.MetaFile), data, 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, vault.MetaFile+".sig"), sig, 0o644); err != nil {
		return err
	}
	if err := commitPush(dir, vs.Branch, []string{vault.MetaFile, vault.MetaFile + ".sig"}); err != nil {
		return err
	}
	_, err = gitx.Run(dir, "read-tree", "HEAD")
	return err
}

// reencryptForward writes a full generation to the current recipient set
// from the mirror (helper-synced repos) or the work tree (backup repos).
func (a *App) reencryptForward(r *repo, _ *vaultState) error {
	vs, err := a.loadVault(r) // fresh: new recipients, new chain tip
	if err != nil {
		return err
	}
	if vs.Chain.Last() == nil {
		a.logf("no generations yet; the next push or backup will use the new recipient set")
		return nil
	}
	status, err := config.LoadStatus(r.Paths)
	if err != nil {
		return err
	}
	ms, _ := config.LoadMirrorState(r.Paths)
	src, withState := r.Work, true
	if ms != nil && ms.AppliedGeneration > 0 {
		if err := a.mirrorSync(r, vs); err != nil {
			return err
		}
		src, withState = r.Paths.Mirror, false
	}
	res, err := a.writeGeneration(r, vs, status, genOptions{Source: src, Full: true, WithState: withState})
	if err != nil {
		return err
	}
	if src == r.Paths.Mirror {
		_ = config.SaveMirrorState(r.Paths, &config.MirrorState{AppliedGeneration: res.Number, AppliedHash: res.ManifestHash})
	}
	a.logf("generation %06d written (full) for the new recipient set", res.Number)
	return nil
}
