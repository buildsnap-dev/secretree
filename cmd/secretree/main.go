// Command secretree is a zero-knowledge off-site git backup tool.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/buildsnap-dev/secretree/internal/app"
)

const usage = `secretree — private git: encrypted repositories on any host, with pull requests, reviews and CI intact

usage: secretree [-C <repo dir>] [-v] <command> [options]

commands:
  init      --vault <url|dir|github:owner/name|gitlab:owner/name> [--kit-out <file>] [--push] [--name <device>] [--label <repo>]
            [--from-recovery-kit <file>] [--repo-id <id>] [--no-remote] [--force]
  kit       --html [<file>] | --print <file> | --confirm   # printable kit with QR codes; confirm once on paper
  backup    [--full]
  verify    [--generation N] [--quick] [--all]
  restore   --vault <url|dir> --to <dir> [--repo-id <id>] [--generation N] [--from-recovery-kit <file>] [--no-state]
  status
  doctor                                     # every check a support request starts with, with the fix
  repair                                     # after the host lost or rewrote generations: rebuild the chain from local data
  demo      [--dir <dir>] [--clean]          # the whole workflow on a throw-away vault, UI at the end
  clone     <vault-url> [dir] [--repo-id <id>] [--from-recovery-kit <file>]
  install-helper [--dir <bindir>]     # makes "git clone secretree::<vault-url>" work
  schedule  --every <duration> | --daily HH:MM | --remove | --show
  join      --vault <url|dir> [--name <device>] [--no-push --out <file>]   # new device: keys + request via the vault
  member    list | pending | approve <name> [--role agent] | deny <name> | add --request <file> [--role agent]
            add --recipient age1... [--signer "..."] --name <n> | remove --name <n> | request
  share     <path> [--ref <ref>] | --diff <a..b> [--expires 7d] [--note <why>] [--out <file.html>]
  ledger    [add --kind export --subject <what> [--note <why>]]   # every deliberate disclosure, signed and chained
  ui        [--listen 127.0.0.1:7391] [--open] | --install | --uninstall   # local code browser + pull requests
  watch     --ntfy <url> | --desktop | --exec <cmd> [--serve :8787] [--include-titles]   # activity notifications
  pr        open --title <t> [--base main] [--head <branch>] | list [--all] | show <#n> | comment <#n> -m <text> [--path f --line n]
            approve <#n> [-m] | request-changes <#n> -m | review <#n> --verdict <v> [-m] | resolve <#n> <comment-id>
            diff <#n> [--stat] | checkout <#n> | merge <#n> [--method merge|squash|ff] | close <#n>
  policy    [--approvals 1] [--checks ci]        # writes .secretree/policy.json (commit it on the base branch)
  runner    [--name ci] [--cmd <sh>] [--branches main] [--interval 60s] [--once]   # CI agent on a key-holding machine
  deploy-agent --to <dir> [--branch main] [--cmd <sh>] [--require-check ci] [--once]  # pull-based CD on the target host
  link      <path>[:<line>] [--ref <ref>]        # permalink into the local UI
  version

The vault is a git repository (SSH/HTTPS URL or a local directory) that only
ever sees ciphertext. With the helper installed, a vault is an ordinary git
remote: git remote add origin secretree::<vault-url>[#<repo-id>]
Docs: https://secretree.dev/docs/
`

func main() {
	// git invokes us as git-remote-secretree <name> <url>
	if base := strings.TrimSuffix(filepath.Base(os.Args[0]), ".exe"); base == app.HelperName && len(os.Args) == 3 {
		a := &app.App{Out: os.Stderr, Err: os.Stderr}
		if err := a.RemoteHelper(os.Args[1], os.Args[2], os.Stdin, os.Stdout); err != nil {
			fmt.Fprintf(os.Stderr, "secretree: %s\n", strings.TrimSpace(err.Error()))
			os.Exit(1)
		}
		return
	}
	global := flag.NewFlagSet("secretree", flag.ContinueOnError)
	global.SetOutput(os.Stderr)
	dir := global.String("C", "", "run as if started in this directory")
	verbose := global.Bool("v", false, "verbose output")
	global.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	if err := global.Parse(os.Args[1:]); err != nil {
		os.Exit(2)
	}
	args := global.Args()
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	a := &app.App{Out: os.Stdout, Err: os.Stderr, Verbose: *verbose}
	cmd, rest := args[0], args[1:]
	var err error
	switch cmd {
	case "init":
		fs := flag.NewFlagSet("init", flag.ExitOnError)
		o := app.InitOptions{Dir: *dir}
		fs.StringVar(&o.VaultURL, "vault", "", "vault git URL or directory")
		fs.StringVar(&o.Label, "label", "", "human label stored (encrypted) in manifests")
		fs.StringVar(&o.KitOut, "kit-out", "", "write the recovery kit to this file instead of stdout")
		fs.StringVar(&o.KitIn, "from-recovery-kit", "", "import keys from a recovery kit (joining an existing vault)")
		fs.StringVar(&o.RepoID, "repo-id", "", "continue an existing chain in the vault")
		fs.BoolVar(&o.Force, "force", false, "overwrite an existing configuration")
		fs.BoolVar(&o.Push, "push", false, "push every branch and tag through the helper right away")
		fs.BoolVar(&o.NoRemote, "no-remote", false, "do not add a git remote or install the helper (backup-only use)")
		fs.StringVar(&o.Remote, "remote", "origin", "name of the git remote to add")
		fs.StringVar(&o.Name, "name", "", "this device's member name, shown on reviews and comments (default: hostname)")
		must(fs.Parse(rest))
		err = a.Init(o)
	case "kit":
		fs := flag.NewFlagSet("kit", flag.ExitOnError)
		pr := fs.String("print", "", "send this recovery kit file to the default printer (or open it)")
		confirm := fs.Bool("confirm", false, "record that the kit is on paper")
		htmlOut := fs.String("html", "", "write a printable kit with QR codes to this file (\"-\" for the default name)")
		must(fs.Parse(rest))
		switch {
		case *htmlOut != "":
			if *htmlOut == "-" {
				*htmlOut = ""
			}
			err = a.KitHTML(*dir, *htmlOut)
		default:
			err = a.Kit(*dir, *pr, *confirm)
		}
	case "watch":
		fs := flag.NewFlagSet("watch", flag.ExitOnError)
		o := app.WatchOptions{Dir: *dir}
		fs.DurationVar(&o.Interval, "interval", 2*time.Minute, "poll interval")
		fs.StringVar(&o.Ntfy, "ntfy", "", "ntfy topic URL (e.g. https://ntfy.sh/team-x7q)")
		fs.StringVar(&o.Exec, "exec", "", "run this command; the message is in $SECRETREE_MESSAGE")
		fs.BoolVar(&o.Desktop, "desktop", false, "desktop notification (macOS / Linux)")
		fs.StringVar(&o.Serve, "serve", "", "also accept host webhooks here, e.g. :8787 (any POST triggers a check)")
		fs.BoolVar(&o.IncludeTitles, "include-titles", false, "include PR titles in messages (they leave the key boundary)")
		fs.BoolVar(&o.Once, "once", false, "learn the current state and exit")
		must(fs.Parse(rest))
		err = a.Watch(o)
	case "backup":
		fs := flag.NewFlagSet("backup", flag.ExitOnError)
		o := app.BackupOptions{Dir: *dir}
		fs.BoolVar(&o.Full, "full", false, "force a full bundle")
		must(fs.Parse(rest))
		err = a.Backup(o)
	case "verify":
		fs := flag.NewFlagSet("verify", flag.ExitOnError)
		o := app.VerifyOptions{Dir: *dir}
		fs.IntVar(&o.Generation, "generation", 0, "generation to rebuild (default latest)")
		fs.BoolVar(&o.Quick, "quick", false, "check signatures, hashes and chain only")
		fs.BoolVar(&o.All, "all", false, "also hash every ciphertext of every generation (catches silent corruption of old blobs)")
		must(fs.Parse(rest))
		err = a.Verify(o)
	case "restore":
		fs := flag.NewFlagSet("restore", flag.ExitOnError)
		o := app.RestoreOptions{}
		fs.StringVar(&o.VaultURL, "vault", "", "vault git URL or directory")
		fs.StringVar(&o.To, "to", "", "new directory for the restored repository")
		fs.StringVar(&o.RepoID, "repo-id", "", "which repository (when the vault holds several)")
		fs.IntVar(&o.Generation, "generation", 0, "generation to restore (default latest)")
		fs.StringVar(&o.KitIn, "from-recovery-kit", "", "recovery kit file")
		fs.BoolVar(&o.NoState, "no-state", false, "do not unpack the state archive")
		must(fs.Parse(rest))
		err = a.Restore(o)
	case "status":
		err = a.Status(*dir)
	case "doctor":
		err = a.Doctor(*dir)
	case "repair":
		err = a.Repair(*dir)
	case "demo":
		fs := flag.NewFlagSet("demo", flag.ExitOnError)
		clean := fs.Bool("clean", false, "remove the demo directory and stop its UI")
		where := fs.String("dir", "", "where to build the demo (default: a temporary directory)")
		must(fs.Parse(rest))
		err = a.Demo(*where, *clean)
	case "clone":
		fs := flag.NewFlagSet("clone", flag.ExitOnError)
		o := app.CloneOptions{}
		fs.StringVar(&o.RepoID, "repo-id", "", "which repository (when the vault holds several)")
		fs.StringVar(&o.KitIn, "from-recovery-kit", "", "recovery kit file to import first")
		pos := parseAll(fs, rest)
		if len(pos) < 1 {
			fmt.Fprintln(os.Stderr, "usage: secretree clone <vault-url> [dir]")
			os.Exit(2)
		}
		o.VaultURL = pos[0]
		if len(pos) > 1 {
			o.Dir = pos[1]
		}
		err = a.Clone(o)
	case "install-helper":
		fs := flag.NewFlagSet("install-helper", flag.ExitOnError)
		d := fs.String("dir", "", "directory for the git-remote-secretree symlink (default: next to this binary)")
		must(fs.Parse(rest))
		err = a.InstallHelperCmd(*d)
	case "remote-helper":
		if len(rest) != 2 {
			fmt.Fprintln(os.Stderr, "usage: secretree remote-helper <name> <url>   (normally invoked by git)")
			os.Exit(2)
		}
		a.Out = os.Stderr
		err = a.RemoteHelper(rest[0], rest[1], os.Stdin, os.Stdout)
	case "schedule":
		fs := flag.NewFlagSet("schedule", flag.ExitOnError)
		o := app.ScheduleOptions{Dir: *dir}
		fs.DurationVar(&o.Every, "every", 0, "interval, e.g. 1h")
		fs.StringVar(&o.Daily, "daily", "", "time of day, HH:MM")
		fs.BoolVar(&o.Remove, "remove", false, "remove the schedule")
		fs.BoolVar(&o.Show, "show", false, "print the installed schedule")
		must(fs.Parse(rest))
		err = a.Schedule(o)
	case "join":
		fs := flag.NewFlagSet("join", flag.ExitOnError)
		o := app.JoinOptions{}
		fs.StringVar(&o.VaultURL, "vault", "", "vault git URL or directory")
		fs.StringVar(&o.Name, "name", "", "this device's name (shown to members)")
		fs.StringVar(&o.Out, "out", "", "write the join request to a file (with --no-push)")
		fs.BoolVar(&o.NoPush, "no-push", false, "do not send the request through the vault; produce a file to send by hand")
		pos := parseAll(fs, rest)
		if o.VaultURL == "" && len(pos) == 1 {
			o.VaultURL = pos[0]
		}
		err = a.Join(o)
	case "member":
		if len(rest) == 0 {
			fmt.Fprintln(os.Stderr, "usage: secretree member list|add|remove|request")
			os.Exit(2)
		}
		sub, subrest := rest[0], rest[1:]
		fs := flag.NewFlagSet("member "+sub, flag.ExitOnError)
		o := app.MemberOptions{Dir: *dir}
		fs.StringVar(&o.Request, "request", "", "join request file")
		fs.StringVar(&o.Recipient, "recipient", "", "age public key")
		fs.StringVar(&o.Signer, "signer", "", "ssh public key line")
		fs.StringVar(&o.Name, "name", "", "member name")
		fs.StringVar(&o.Role, "role", "", "\"agent\" for AI or bot members: may comment and review, approvals do not count, cannot merge")
		if (sub == "approve" || sub == "deny") && len(subrest) > 0 && !strings.HasPrefix(subrest[0], "-") {
			must(fs.Parse(subrest[1:]))
		} else {
			must(fs.Parse(subrest))
		}
		switch sub {
		case "list":
			err = a.MemberList(*dir)
		case "add":
			err = a.MemberAdd(o)
		case "remove":
			err = a.MemberRemove(o)
		case "request":
			err = a.MemberRequest(*dir)
		case "pending":
			err = a.MemberPending(*dir)
		case "approve":
			if len(subrest) == 0 || strings.HasPrefix(subrest[0], "-") {
				fmt.Fprintln(os.Stderr, "usage: secretree member approve <name|id> [--role agent]")
				os.Exit(2)
			}
			err = a.MemberApprove(*dir, subrest[0], o.Role)
		case "deny":
			if len(subrest) == 0 {
				fmt.Fprintln(os.Stderr, "usage: secretree member deny <name|id>")
				os.Exit(2)
			}
			err = a.MemberDeny(*dir, subrest[0])
		default:
			fmt.Fprintln(os.Stderr, "usage: secretree member list|pending|approve|deny|add|remove|request")
			os.Exit(2)
		}
	case "share":
		fs := flag.NewFlagSet("share", flag.ExitOnError)
		o := app.ShareOptions{Dir: *dir}
		fs.StringVar(&o.Ref, "ref", "", "ref or commit (default HEAD)")
		fs.StringVar(&o.Diff, "diff", "", "share a diff: <a..b> or a commit")
		fs.DurationVar(&o.Expires, "expires", 7*24*time.Hour, "advisory expiry (0 = none)")
		fs.StringVar(&o.Note, "note", "", "why this is being shared (goes into the ledger)")
		fs.StringVar(&o.Out, "out", "", "output HTML file")
		fs.BoolVar(&o.NoLedger, "no-ledger", false, "do not record the disclosure (not recommended)")
		pos := parseAll(fs, rest)
		if len(pos) > 0 {
			o.Path = pos[0]
		}
		err = a.Share(o)
	case "ledger":
		if len(rest) > 0 && rest[0] == "add" {
			fs := flag.NewFlagSet("ledger add", flag.ExitOnError)
			kind := fs.String("kind", "export", "share | export | public-mirror")
			subject := fs.String("subject", "", "what left, e.g. \"diff #7 → claude\"")
			note := fs.String("note", "", "why")
			must(fs.Parse(rest[1:]))
			err = a.LedgerAdd(*dir, *kind, *subject, *note)
		} else {
			err = a.Ledger(*dir)
		}
	case "ui":
		fs := flag.NewFlagSet("ui", flag.ExitOnError)
		o := app.UIOptions{Dir: *dir}
		fs.StringVar(&o.Listen, "listen", app.DefaultUIAddr, "address to listen on (keep it loopback unless on a private network)")
		fs.BoolVar(&o.Open, "open", false, "open in the browser")
		install := fs.Bool("install", false, "run the UI as a background service (launchd / systemd --user)")
		uninstall := fs.Bool("uninstall", false, "remove the background service")
		must(fs.Parse(rest))
		switch {
		case *install:
			err = a.UIInstall(*dir, o.Listen, false)
		case *uninstall:
			err = a.UIInstall(*dir, o.Listen, true)
		default:
			err = a.UI(o)
		}
	case "link":
		fs := flag.NewFlagSet("link", flag.ExitOnError)
		ref := fs.String("ref", "", "ref (default: current commit, for a permanent link)")
		pos := parseAll(fs, rest)
		if len(pos) != 1 {
			fmt.Fprintln(os.Stderr, "usage: secretree link <path>[:<line>] [--ref <ref>]")
			os.Exit(2)
		}
		err = a.Link(*dir, pos[0], *ref)
	case "pr":
		if len(rest) == 0 {
			fmt.Fprintln(os.Stderr, "usage: secretree pr open|list|show|diff|checkout|comment|review|approve|request-changes|resolve|merge|close")
			os.Exit(2)
		}
		sub, subrest := rest[0], rest[1:]
		fs := flag.NewFlagSet("pr "+sub, flag.ExitOnError)
		title := fs.String("title", "", "title")
		body := fs.String("body", "", "description")
		msg := fs.String("m", "", "message")
		base := fs.String("base", "", "base branch (default main)")
		head := fs.String("head", "", "head branch (default current)")
		path := fs.String("path", "", "file the comment refers to")
		line := fs.Int("line", 0, "line the comment refers to")
		all := fs.Bool("all", false, "include merged and closed")
		method := fs.String("method", "merge", "merge | squash | ff")
		verdict := fs.String("verdict", "", "approve | request_changes | comment (for: pr review)")
		stat := fs.Bool("stat", false, "diffstat only (for: pr diff)")
		pos := parseAll(fs, subrest)
		ref := ""
		if len(pos) > 0 {
			ref = pos[0]
		}
		switch sub {
		case "open":
			if *title == "" && ref != "" {
				*title = ref
			}
			err = a.PROpen(app.PROpenOptions{Dir: *dir, Title: *title, Body: *body, Base: *base, Head: *head})
		case "list":
			err = a.PRList(*dir, *all)
		case "show":
			err = a.PRShow(*dir, ref)
		case "comment":
			err = a.PRComment(*dir, ref, *msg, *path, *line)
		case "approve":
			err = a.PRReview(*dir, ref, "approve", *msg)
		case "request-changes":
			err = a.PRReview(*dir, ref, "request_changes", *msg)
		case "review":
			err = a.PRReview(*dir, ref, *verdict, *msg)
		case "resolve":
			if len(pos) < 2 {
				fmt.Fprintln(os.Stderr, "usage: secretree pr resolve <#n> <comment-id>")
				os.Exit(2)
			}
			err = a.PRResolve(*dir, ref, pos[1])
		case "merge":
			err = a.PRMerge(*dir, ref, *method)
		case "close":
			err = a.PRClose(*dir, ref)
		case "checkout":
			err = a.PRCheckout(*dir, ref)
		case "diff":
			err = a.PRDiff(*dir, ref, *stat)
		default:
			fmt.Fprintln(os.Stderr, "usage: secretree pr open|list|show|diff|checkout|comment|review|approve|request-changes|resolve|merge|close")
			os.Exit(2)
		}
	case "policy":
		fs := flag.NewFlagSet("policy", flag.ExitOnError)
		approvals := fs.Int("approvals", 1, "required approvals")
		checks := fs.String("checks", "ci", "comma-separated required checks (\"\" for none)")
		must(fs.Parse(rest))
		var cs []string
		for _, c := range strings.Split(*checks, ",") {
			if c = strings.TrimSpace(c); c != "" {
				cs = append(cs, c)
			}
		}
		err = a.PolicyInit(*dir, *approvals, cs)
	case "runner":
		fs := flag.NewFlagSet("runner", flag.ExitOnError)
		o := app.RunnerOptions{Dir: *dir}
		fs.StringVar(&o.Name, "name", "ci", "check name")
		fs.StringVar(&o.Cmd, "cmd", "", "pipeline command (default: .secretree/ci, then make ci)")
		branches := fs.String("branches", "main", "comma-separated branches to always check")
		fs.DurationVar(&o.Interval, "interval", 60*time.Second, "poll interval")
		fs.DurationVar(&o.Timeout, "timeout", 30*time.Minute, "per-job timeout")
		fs.BoolVar(&o.Once, "once", false, "one pass, then exit")
		must(fs.Parse(rest))
		o.Branches = strings.Split(*branches, ",")
		err = a.Runner(o)
	case "deploy-agent":
		fs := flag.NewFlagSet("deploy-agent", flag.ExitOnError)
		o := app.DeployOptions{Dir: *dir}
		fs.StringVar(&o.Branch, "branch", "main", "branch to deploy")
		fs.StringVar(&o.To, "to", "", "target directory")
		fs.StringVar(&o.Cmd, "cmd", "", "command to run in the target after export")
		fs.StringVar(&o.RequireCheck, "require-check", "ci", "deploy only when this check is green (\"\" for none)")
		fs.DurationVar(&o.Interval, "interval", 60*time.Second, "poll interval")
		fs.BoolVar(&o.Once, "once", false, "one pass, then exit")
		must(fs.Parse(rest))
		err = a.DeployAgent(o)
	case "version":
		fmt.Println("secretree", app.Version)
	case "help", "-h", "--help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", cmd, usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "secretree %s: %s\n", cmd, strings.TrimSpace(err.Error()))
		os.Exit(1)
	}
}

func must(err error) {
	if err != nil {
		os.Exit(2)
	}
}

// parseAll lets flags and positional arguments be interleaved, the way
// git's own commands behave: `secretree share src/x.go --out page.html`.
func parseAll(fs *flag.FlagSet, args []string) []string {
	var positional []string
	for {
		must(fs.Parse(args))
		if fs.NArg() == 0 {
			return positional
		}
		positional = append(positional, fs.Arg(0))
		args = fs.Args()[1:]
	}
}
