package app

import (
	"bytes"
	"errors"
	"fmt"
	"net/http"
	"os/exec"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/buildsnap-dev/secretree/internal/collab"
	"github.com/buildsnap-dev/secretree/internal/config"
	"github.com/buildsnap-dev/secretree/internal/gitx"
)

// WatchOptions configures Watch.
type WatchOptions struct {
	Dir           string
	Interval      time.Duration // poll interval (default 2m)
	Ntfy          string        // ntfy topic URL, e.g. https://ntfy.sh/my-team-x7
	Exec          string        // shell command; the message is $SECRETREE_MESSAGE
	Desktop       bool          // macOS / Linux desktop notification
	Serve         string        // also listen here for host webhooks (any POST triggers a check)
	IncludeTitles bool          // put PR titles in notifications (they leave the key boundary)
	Once          bool
}

// Watch notices new collaboration activity (pull requests, comments,
// reviews, checks, deploys) and pushes the news out. Messages carry only
// numbers and kinds unless --include-titles is given; the host, ntfy and
// the notification centre learn nothing about the code.
func (a *App) Watch(o WatchOptions) error {
	if o.Interval == 0 {
		o.Interval = 2 * time.Minute
	}
	if o.Ntfy == "" && o.Exec == "" && !o.Desktop {
		return errors.New("choose at least one sink: --ntfy <url>, --exec <cmd>, or --desktop")
	}
	r, err := a.openRepo(o.Dir)
	if err != nil {
		return err
	}
	kick := make(chan struct{}, 1)
	if o.Serve != "" {
		mux := http.NewServeMux()
		mux.HandleFunc("POST /", func(w http.ResponseWriter, _ *http.Request) {
			select {
			case kick <- struct{}{}:
			default:
			}
			w.WriteHeader(204)
		})
		go func() {
			a.logf("watch: webhook listener on %s (any POST triggers a check)", o.Serve)
			_ = http.ListenAndServe(o.Serve, mux)
		}()
	}
	seen, err := a.watchPass(r, o, nil)
	if err != nil {
		return err
	}
	a.logf("watch: %d event(s) known, waiting for new ones", len(seen))
	if o.Once {
		return nil
	}
	for {
		select {
		case <-time.After(o.Interval):
		case <-kick:
		}
		if seen, err = a.watchPass(r, o, seen); err != nil {
			a.logf("watch: %v", err)
		}
	}
}

// watchPass fetches, folds new events into human lines and notifies.
// A nil seen set means "learn the current state, notify about nothing".
func (a *App) watchPass(r *repo, o WatchOptions, seen map[string]bool) (map[string]bool, error) {
	vs, err := a.loadVault(r)
	if err != nil {
		return seen, err
	}
	remote := secretreeRemote(r.Work)
	if remote != "" {
		if _, err := gitx.Run(r.Work, "fetch", "--quiet", remote); err != nil {
			return seen, err
		}
	}
	store := a.collabStore(r, vs)
	removed, err := store.Sync(remote)
	if err != nil {
		return seen, err
	}
	a.reportRemovals(removed)
	events, _, err := store.Events()
	if err != nil {
		return seen, err
	}
	nameEvents(vs, events)
	prs := collab.Fold(events)
	title := map[string]string{}
	number := map[string]int{}
	for _, pr := range prs {
		title[pr.ID], number[pr.ID] = pr.Title, pr.Number
	}
	now := map[string]bool{}
	var fresh []collab.Event
	me, _ := r.Keys.Fingerprint()
	for _, e := range events {
		now[e.ID] = true
		if seen != nil && !seen[e.ID] && e.Actor != me {
			fresh = append(fresh, e)
		}
	}
	if len(fresh) == 0 {
		return now, nil
	}
	lines := summarize(fresh, number, title, o.IncludeTitles)
	msg := strings.Join(lines, "\n")
	a.logf("watch: %s", strings.ReplaceAll(msg, "\n", " · "))
	if o.Ntfy != "" {
		req, _ := http.NewRequest("POST", o.Ntfy, bytes.NewReader([]byte(msg)))
		req.Header.Set("Title", "secretree: "+r.Cfg.Label)
		if resp, err := http.DefaultClient.Do(req); err != nil {
			a.logf("watch: ntfy: %v", err)
		} else {
			resp.Body.Close()
		}
	}
	if o.Desktop {
		notifyDesktop("secretree: "+r.Cfg.Label, msg)
	}
	if o.Exec != "" {
		cmd := gitx.ShellCommand(o.Exec)
		cmd.Env = append(gitx.Env(), "SECRETREE_MESSAGE="+msg, "SECRETREE_REPO="+r.Cfg.Label)
		if out, err := cmd.CombinedOutput(); err != nil {
			a.logf("watch: exec: %v %s", err, strings.TrimSpace(string(out)))
		}
	}
	return now, nil
}

// summarize turns events into short lines, grouped per PR.
func summarize(events []collab.Event, number map[string]int, title map[string]string, titles bool) []string {
	type key struct{ pr, kind string }
	counts := map[key]int{}
	who := map[key]string{}
	for _, e := range events {
		k := key{e.PR, e.Kind}
		if e.Kind == collab.KindReview {
			k.kind = e.Verdict
		}
		if e.Kind == collab.KindState {
			k.kind = e.State
		}
		if e.Kind == collab.KindCheck || e.Kind == collab.KindDeploy {
			k.kind = e.Kind + " " + e.Status
		}
		counts[k]++
		if e.ActorName != "" {
			who[k] = e.ActorName
		}
	}
	var lines []string
	for k, n := range counts {
		label := "repository"
		if k.pr != "" {
			label = fmt.Sprintf("PR #%d", number[k.pr])
			if titles && title[k.pr] != "" {
				label += " (" + title[k.pr] + ")"
			}
		}
		verb := k.kind
		switch k.kind {
		case collab.KindPR:
			verb = "opened"
		case collab.KindComment:
			verb = "new comment"
		case collab.VerdictApprove:
			verb = "approved"
		case collab.VerdictRequestChanges:
			verb = "changes requested"
		}
		if n > 1 {
			verb = fmt.Sprintf("%s ×%d", verb, n)
		}
		if w := who[k]; w != "" {
			verb += " by " + w
		}
		lines = append(lines, label+": "+verb)
	}
	sort.Strings(lines)
	return lines
}

func notifyDesktop(title, body string) {
	switch runtime.GOOS {
	case "darwin":
		script := fmt.Sprintf(`display notification %q with title %q`, body, title)
		_ = exec.Command("osascript", "-e", script).Run()
	case "linux":
		_ = exec.Command("notify-send", title, body).Run()
	}
}

var _ = config.Dir
