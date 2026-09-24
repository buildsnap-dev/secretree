# Decision log

Format: short ADR entries, newest last. Status: **accepted** / **proposed** /
**superseded**.

## 0001 — Name: secretree — accepted (2026-09-15)

The predecessor was a ~100-line private shell script (git bundle, openssl
AES-CBC with a Keychain passphrase, an append-only mirror repo on GitLab).
secretree is an independent, standalone open-source project.

## 0002 — License: MIT — accepted (2026-09-15)

Chosen over Apache-2.0 for simplicity and to match age/rage's dual licensing.
Trivial to change while there are no outside contributors.

## 0003 — Vault format v1 frozen before code — accepted (2026-09-15)

The format is the product; the tool is replaceable. v1 is specified in
[vault-format.md](vault-format.md) with a hand-restore procedure using only
`git`, `age`, `ssh-keygen` and `shasum`. Any change that breaks hand-restore
of an existing vault is a v2 and requires a migration command.

## 0004 — age for encryption, OpenSSH signatures for authenticity — accepted (2026-09-15)

Rationale in [threat-model.md](threat-model.md). Rejected: OpenPGP
(git-remote-gcrypt's choice; key management is the reason gcrypt never
became mainstream), minisign (an extra binary to install on the disaster
machine), home-grown AES-CBC + PBKDF2 (the predecessor; unauthenticated).

## 0005 — Encrypt-then-sign, signatures over ciphertext — accepted (2026-09-15)

Allows chain integrity checks without the decryption key. See threat model.

## 0006 — Append-only remote, protected branch — accepted (2026-09-15)

Inherited from the predecessor and kept: every backup is a new commit, the
tool never force-pushes. Growth is bounded by periodic new full bundles;
pruning old chains is a phase-2 concern and will be done by starting a new
vault branch, never by rewriting.

## 0007 — Implementation language: Go — accepted (2026-09-15)

Owner's decision after weighing the candidates below. Go 1.27 is installed
under `~/sdk/go` (no Homebrew on the machine); `PATH` is set in `~/.zshrc`.
Module path is the bare name `secretree` until a public home is chosen.

Candidates were:

- **Go** (recommended in the handoff): one static binary per platform, the
  reference age implementation is a Go library (`filippo.io/age`), OpenSSH
  signature format has a Go implementation (`github.com/hiddeco/sshsig`),
  the git remote-helper protocol is plain stdin/stdout. Cost: the Go
  toolchain is not installed on the development machine; requires a
  download from go.dev (~75 MB, no Homebrew present).
- **Python 3.12 via uv**: already installed, matches the owner's other
  projects, `pyrage` wraps the audited Rust rage implementation, signing via
  `ssh-keygen -Y` subprocess. Cost: distribution is `uv tool install`, not a
  single binary; startup latency matters for a remote helper; less credible
  as a public security tool.
- **Rust**: rage is native, single binary, but no toolchain installed and
  slowest iteration for a weekend MVP.

Everything in `docs/` stays language-neutral.

## 0008 — Key stores — accepted for MVP (2026-09-15)

MVP: macOS Keychain (`security` CLI or Security.framework), item per key,
service `secretree`, account `<vault-id>/<key-role>`. Phase 2: Linux
Secret Service (D-Bus), Windows Credential Manager. Hardware-backed keys
(Secure Enclave via an age plugin, TPM) are phase 2+.

## 0009 — MVP targets — accepted for MVP (2026-09-15)

Remote types in the MVP: any git remote (SSH or HTTPS URL) and a local
directory (which is just a bare git repo on disk, so it is the same code
path and the natural test fixture). S3/rclone targets are phase 2; the
format is designed so a target only needs "put file" and "list/get files".

## 0010 — Vault clones are partial and checkout-less — accepted (2026-09-15)

Both the persistent cache under `.git/secretree/vault-cache` and the fresh
clone made for every restore proof use `git clone --no-checkout
--filter=blob:none`, falling back to a plain no-checkout clone when the
server rejects filters. Manifests and only the bundles a restore needs are
fetched on demand, so the proof costs a few small blobs plus one chain of
bundles, not the whole vault. New generations are committed from the index
(`git read-tree HEAD` + `git add`), which needs no checkout either. Local
bare vaults are created with `uploadpack.allowFilter`, `receive.denyDeletes`
and `receive.denyNonFastForwards` set.

## 0011 — Generations may carry no bundle — accepted (2026-09-15)

A generation whose only change is a ref move onto existing objects (branch
created, deleted or renamed) or a state-archive change has no bundle file;
the manifest's ref map is authoritative. `git bundle` refuses to write an
empty bundle, and the alternative (forcing a full) would bloat the vault for
nothing. A `full` generation always carries a bundle.

## 0012 — Plaintext scratch space lives under `.git/secretree/tmp` — accepted, revisit (2026-09-15)

Bundles and state archives exist in plaintext for the duration of a run in
a 0700 directory inside the repository's git dir, on the same disk as the
source itself, so no new exposure is created. A RAM-backed location
(tmpfs, macOS `hdiutil` ram disk) is a planned hardening for the runner and
restore-on-foreign-machine cases, where the disk is not already trusted.

## 0013 — Scope: a private-git product, not a backup tool — accepted (2026-09-15)

Owner's direction: a standalone open-source product that keeps source code
encrypted everywhere outside key-holding machines *without* degrading the
developer experience, including pull requests, reviews and CI/CD. The vault
format and backup command stay as layer 1; the same chain becomes the sync
primitive for a git remote helper, and collaboration data rides on it.
Architecture and roadmap: [vision.md](vision.md).

## 0014 — Collaboration data lives in git, clients enforce policy — accepted (2026-09-15)

PRs, reviews, approvals and check results are signed git objects under
`refs/secretree/collab/*`, encrypted and synced like source (the
git-appraise / git-bug approach). No server ever holds plaintext, and
policy (approvals, green CI before merge) is verifiable by every client
because the inputs are signed. The user-facing surface is a local web UI,
an IDE extension and the CLI. A self-hosted forge behind the key remains a
documented alternative, not the product.

## 0015 — CI runs where the key is; the host is a webhook — accepted (2026-09-15)

A runner agent on hardware the team controls decrypts into RAM and executes
the team's existing pipeline files (`act` for GitHub workflows, make/just).
Logs and artifacts go back encrypted. Registering as a host's self-hosted
runner is a supported hybrid with documented metadata leakage. Keys are
never placed in a host's secrets store.

## 0016 — Remote helper uses fetch/push, not connect — accepted (2026-09-15)

The helper implements `list`, `fetch` and `push` and moves objects with an
internal `git fetch`/`git push` against the local mirror. `connect` would
have been fewer lines but reports vault-level rejections only through the
helper's exit status, after git already printed success. With `push`, a
rejected vault append is reported per ref the way any remote reports a
non-fast-forward.

## 0017 — Per-device keys; late members see an opaque past — accepted (2026-09-15)

Every device generates its own age identity and signing key (`join`). A
member added later cannot read generations encrypted before their key was
a recipient; those are verified but opaque, and `member add` writes a full
generation to the new set at once. Re-encrypting history for newcomers is
a deliberate, separate action (not yet implemented), never a side effect.

## 0018 — Revocation keeps old signatures valid up to a cut-off — accepted (2026-09-15)

Removing a member moves their signer line into `revoked_signers` with the
last generation and ledger entry they may have signed. History stays
verifiable; a revoked key that still has host push access cannot append
anything the other members will accept.

## 0019 — Share pages are self-contained files with the key in the fragment — accepted (2026-09-15)

No secretree-hosted viewer and no dependency on the vault host serving
plaintext-fetchable blobs: the page carries viewer and ciphertext, decrypts
in the browser with age-encryption (loaded from jsDelivr, pinned by
version; self-hosting the viewer is the hardening path). Every share is a
ledger entry.

## 0020 — Local UI is read-only and loopback by default — accepted (2026-09-15)

`secretree ui` serves the mirror on 127.0.0.1 with forge-shaped URLs. A
non-loopback listen address is allowed for private networks and prints a
warning. Writes (PRs, reviews) will come with the collaboration layer.

## 0021 — Pull requests are events in a git ref, merged by union — accepted (2026-09-15)

`refs/secretree/collab` holds signed JSON events with unique file names.
No sequence numbers to allocate, no server: concurrent writers merge with
`git merge-tree`, and the helper's push rejection only ever means "fetch
and merge the union", which the `pr` commands do automatically (three
attempts). PR numbers are advisory; the directory id carries a random
suffix so simultaneous opens cannot collide.

## 0022 — Policy is enforced by clients and verifiable by clients — accepted (2026-09-15)

`secretree pr merge` refuses to merge without the approvals and green
checks that `.secretree/policy.json` requires, counting only reviews and
checks of the *current* head commit. Because those are signed events,
any client can recompute the verdict. A rogue client can still push a
merge commit directly with git; that is visible (no matching state event,
or a state event whose inputs do not satisfy policy) rather than
preventable, and preventing it is a host-side branch protection concern.

## 0023 — The runner is a plain agent, not a workflow engine — accepted (2026-09-15)

The runner executes what the repository already has (`.secretree/ci`,
`make ci`, or a command) in a detached worktree and records one signed
check with the log. Matrix builds, caching and orchestration belong to
the pipeline script or to `act`; the runner's job is to be the place
where the key is. Logs are events in the collab ref and therefore
encrypted at rest on the host.

## 0024 — Deploy is pull-based and gated on a signed check — accepted (2026-09-15)

The deploy agent runs on the target, exports a branch tip with
`git archive` (no `.git` on the server), and records a signed deploy
event. It refuses commits without the required green check. CI holds no
production credentials; the target needs no inbound access.

## 0025 — `init` does the whole first mile — accepted (2026-09-15)

`init` creates the host repository when given `github:owner/name` or
`gitlab:owner/name` (private, `main` protected via the `gh`/`glab` CLI),
installs the helper next to the binary, adds the `origin` remote and, with
`--push`, pushes every branch and tag. A vault that was created here is
flagged until `kit --confirm` records that the recovery kit is on paper;
`status` nags until then. Rationale: the first five minutes decide
whether a safety tool gets used at all.

## 0026 — Notifications carry counts and kinds, not content — accepted (2026-09-15)

`watch` polls the vault (or is kicked by a host webhook on `--serve`) and
emits lines like "PR #3: new comment ×2 by bob" to ntfy, the desktop or a
command. Titles are included only with `--include-titles`, because they
leave the key boundary. Own events are never announced.

## 0027 — Verified manifests are cached by blob id — accepted (2026-09-15)

Loading a chain used to cost two `git cat-file` calls and an age
decryption per generation. Manifests that this key has already verified
and decrypted are cached under `.git/secretree/manifest-cache/<key fp>/`
keyed by the vault blob id, so a reload is one `git ls-tree` plus the hash
chain check. The cache is per key (a different key must not inherit
another's decryptions) and is ignored when unreadable.

## 0028 — Late members and history: no re-encryption needed — accepted (2026-09-15)

Earlier notes suggested re-encrypting old generations for members added
later. Unnecessary: the full generation written by `member add` carries
the complete git history. Only earlier *backup snapshots* stay opaque to
the newcomer, which is the intended property.

## 0029 — Agents are members with a role, not integrations — accepted (2026-09-15)

An AI reviewer joins like a device (`join`, `member add --role agent`),
runs as a runner job with the PR context in the environment, and writes
signed comments and verdicts. Its approvals never count, it cannot merge.
Sending a diff to a hosted model is a disclosure and the agent records it
in the ledger before doing so.

## 0030 — Line comments follow the code; changed lines are outdated — accepted (2026-09-15)

A comment is anchored to `path:line@commit`. On a newer head it is mapped
through `git diff -U0 <commit> <head>`: unchanged lines are followed to
their new number (shown inline, marked), lines inside a changed hunk make
the comment "outdated" (conversation only). Threads are resolved by a
signed `resolve` event referencing the comment id.

## 0031 — Code on GitHub, website on GitLab + Vercel — accepted (2026-09-18)

The tool's source is public at github.com/buildsnap-dev/secretree (module
path matches, so `go install …@latest` works; releases via goreleaser on
tags). The website lives in its own repository, gitlab.com/andras.palinkas/
secretree-site, deployed by Vercel on every push to `main` at
https://secretree-site.vercel.app. The `site/` directory was removed from
the code repository to avoid two copies drifting.

## 0032 — Renamed to secretree — accepted (2026-09-18)

The project, binary, remote-helper scheme (`secretree::`), key-store
service, local state directory (`.git/secretree/`), policy directory
(`.secretree/`), collaboration ref (`refs/secretree/collab`), format ids
(`secretree-vault/1`, `secretree-manifest/1`, `secretree-ledger/1`) and
signature namespace (`secretree-v1`) all changed from the earlier name in
one go, while no vaults exist outside the author's tests. "Git" is a
trademark of the Software Freedom Conservancy; a name that does not
contain it is cleaner to own and to search for. Vaults written by 0.1.0
are not readable by 0.2.0 and are not meant to be migrated.

## 0033 — The UI shows the guarantees, not only the code — accepted (2026-09-18)

Two pages make the product's promises visible where people already look:
`/vault` (the remote as the host sees it: the real file listing, the
generations, `vault.json`, last backup and last proof) and `/ledger`
(every deliberate disclosure). The header carries a restore-proof badge
on every page. Syntax highlighting is a small Go tokenizer, Markdown for
pull request text is goldmark without raw HTML; no scripts are loaded
from anywhere.

## 0034 — `doctor` is the first support step — accepted (2026-09-18)

`secretree doctor` checks git, the helper, the key store, the repository
configuration, the vault and chain, the recovery kit, the restore proof,
policy, pipeline and the UI, and prints the fix next to each failure.

## 0035 — Releases are signed keylessly and carry an SBOM — accepted (2026-09-18)

`checksums.txt` is signed with cosign in keyless mode from the release
workflow (certificate bound to the repository's workflow identity), and
every archive gets an SPDX SBOM from syft. A Homebrew cask is generated on
every release and pushed to `buildsnap-dev/homebrew-tap` when the
`HOMEBREW_TAP_TOKEN` secret exists; without it the cask is only attached
to the release. macOS notarization needs an Apple Developer account and
is not done yet.

## 0036 — The walkthrough ships inside the binary — accepted (2026-09-18)

`secretree demo` runs the embedded tour script with the running binary,
so a downloaded release can show the whole workflow without a Go
toolchain or a checkout.

## 0037 — Join requests travel through the vault — accepted (2026-09-19)

A joining device encrypts its public keys to the current recipients (they
are in the plaintext `vault.json`) and pushes `requests/<id>.json.age`;
members list them with `member pending` and `member approve` adds the
member and removes the file. No request file needs to be sent by hand.
The host sees one more random file name. `join --no-push` keeps the old
file-based path for hosts where the joiner has no push access.

## 0038 — Devices have member names; the creator is a member too — accepted (2026-09-19)

Reviews, comments, checks and ledger entries carry the device's member
name from `vault.json`, resolved by signer fingerprint at read time, not
the repository label (which is the same for every clone). `init --name`
sets the creator's name (default: hostname) and records it as the first
member.

## 0039 — The UI has its own design and shows activity — accepted (2026-09-19)

The local UI uses the website's palette (paper and ink, a teal accent,
gold for ciphertext), tabs with counts, cards, a timeline for
conversations, empty states that say what to do next, and an Activity
page whose unread badge is computed in the browser from a timestamp in
localStorage; the server keeps no per-viewer state. `kit --html` writes a
printable recovery kit with QR codes that also works as
`--from-recovery-kit` input.

## 0040 — Collaboration history is append-only on the receiving side too — accepted (2026-09-19)

Event files are unique and never edited, so any sync can check that
everything it already knows is still present upstream. When a remote
writer dropped files (a rewritten ref, a "cleanup"), the client takes
the union instead of fast-forwarding, restores the files from its own
objects, pushes the union back, and reports the deleting commit and its
author. A deletion therefore never sticks for anyone who had synced
before; it only announces who tried.

## 0041 — Vault rollback is refused, `repair` rebuilds — accepted (2026-09-19)

Every device records the number and manifest hash of the newest
generation it wrote or saw. When the host's chain no longer contains
it (shorter chain, or a different manifest at that number), every
command refuses to continue with a message naming the gap, instead of
silently appending on top of rewritten history. `secretree repair`
accepts the remaining verified chain and writes a new full generation
from the local mirror (every ref, collaboration included) or work tree,
then runs the restore proof. Other members' next sync adopts it.
