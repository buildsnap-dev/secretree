# secretree — notes for coding agents

Private git in Go: encrypted repositories on any host with PRs, reviews and CI intact. Module path github.com/buildsnap-dev/secretree; public repo on GitHub, website source on GitLab (andras.palinkas/secretree-site) deployed by Vercel to https://secretree.dev. Docs first: `docs/vault-format.md` is the
frozen v1 contract; do not change what lands on the remote without a
decision entry in `docs/decisions.md` and an update to
`docs/restore-by-hand.md`.

## Build and test

Go is installed under `~/sdk/go` (no Homebrew on this machine):

    export PATH="$HOME/sdk/go/bin:$PATH"
    go vet ./... && go test ./...
    go build -trimpath -ldflags="-s -w" -o bin/secretree ./cmd/secretree

Tests are integration tests with real git repositories and a local bare
vault (`internal/app/app_test.go`). They set `SECRETREE_KEYSTORE=file` and a
temporary `SECRETREE_HOME`, so they never touch the macOS Keychain.

## Layout

- `cmd/secretree` — flag parsing only.
- `internal/app` — one file per command; `remote.go` handles vault clones.
- `internal/vault` — format types, chain verification (`chain.go`), rebuild.
- `internal/crypt` — age + SSHSIG plumbing; no cryptography of its own.
- `internal/keys`, `internal/keystore` — key generation, recovery kit, Keychain/file store.
- `internal/gitx` — every git invocation; secretree never parses packs.
- `internal/archive` — deterministic tar+zstd for out-of-repo state.

## Rules

- Never weaken a verification step to make a test pass; the product is the
  restore proof.
- This is a standalone open-source product. Keep it free of references to
  the author's private projects.
