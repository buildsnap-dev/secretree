package app

import (
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"strconv"
	"time"

	"github.com/buildsnap-dev/secretree/internal/collab"
)

// The activity page lists collaboration events across all pull requests,
// newest first; the tab badge counts events newer than the viewer's last
// visit (kept in the browser, never on the server).

type activityRow struct {
	When, Who, Initials, Verb, PRTitle, PRID, Detail string
	Number                                           int
	Agent                                            bool
	Unix                                             int64
}

type activityPage struct {
	chrome
	Title string
	Rows  []activityRow
}

func (s *uiServer) activityRows(sync bool) ([]activityRow, error) {
	rp, err := s.app.openRepoAt(s.work, s.paths.Root+"/..")
	if err != nil {
		return nil, err
	}
	var events []collab.Event
	var agents map[string]bool
	if sync {
		c, err := s.app.openPR(s.work)
		if err != nil {
			return nil, err
		}
		events, agents = c.events, c.agents
	} else {
		vs, err := s.app.loadVaultLocal(rp)
		if err != nil {
			return nil, err
		}
		events, _, err = s.app.collabStore(rp, vs).Events()
		if err != nil {
			return nil, err
		}
		nameEvents(vs, events)
		agents = map[string]bool{}
		for _, m := range vs.Meta.Members {
			if m.Role == "agent" {
				agents[m.SignerFingerprint] = true
			}
		}
	}
	prs := collab.Fold(events)
	title := map[string]string{}
	number := map[string]int{}
	for _, pr := range prs {
		title[pr.ID], number[pr.ID] = pr.Title, pr.Number
	}
	var rows []activityRow
	for i := len(events) - 1; i >= 0; i-- {
		e := events[i]
		who := e.ActorName
		if who == "" {
			who = e.Actor
		}
		row := activityRow{When: e.Created.Format("2006-01-02 15:04"), Unix: e.Created.Unix(), Who: who, Initials: initials(who), Agent: agents[e.Actor],
			PRID: e.PR, PRTitle: title[e.PR], Number: number[e.PR]}
		switch e.Kind {
		case collab.KindPR:
			row.Verb = "opened"
		case collab.KindComment:
			row.Verb = "commented"
			if e.Path != "" {
				row.Detail = fmt.Sprintf("%s:%d", e.Path, e.Line)
			}
		case collab.KindReview:
			switch e.Verdict {
			case collab.VerdictApprove:
				row.Verb = "approved"
			case collab.VerdictRequestChanges:
				row.Verb = "requested changes on"
			default:
				row.Verb = "reviewed"
			}
		case collab.KindState:
			row.Verb = e.State
		case collab.KindCheck:
			row.Verb = "check " + e.Name + ": " + e.Status
			row.Detail = e.Summary
		case collab.KindDeploy:
			row.Verb = "deployed " + e.Name + ": " + e.Status
			row.Detail = e.Target
		case collab.KindResolve:
			row.Verb = "resolved a thread on"
		default:
			continue
		}
		rows = append(rows, row)
	}
	return rows, nil
}

func (s *uiServer) activity(w http.ResponseWriter, r *http.Request) {
	rows, err := s.activityRows(true)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	p := &activityPage{chrome: s.chrome("activity"), Title: "activity", Rows: rows}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", uiCSP)
	if err := activityTmpl.Execute(w, p); err != nil {
		http.Error(w, err.Error(), 500)
	}
}

// activityJSON answers the tab badge: how many events are newer than `since` (unix seconds).
func (s *uiServer) activityJSON(w http.ResponseWriter, r *http.Request) {
	since, _ := strconv.ParseInt(r.URL.Query().Get("since"), 10, 64)
	rows, err := s.activityRows(false)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	n := 0
	for _, row := range rows {
		if row.Unix > since {
			n++
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"count": n, "now": time.Now().Unix()})
}

var activityTmpl = template.Must(template.New("activity").Parse(`<!doctype html>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{{.Repo}}: activity</title>
` + uiCSS + uiHeader + `
<main>
<h1>Activity</h1>
<p class="lead">Every signed event on this repository's pull requests, checks and deployments, newest first. Your own device's events are included; the badge on the tab counts only what happened since you last looked.</p>
<div class="card">{{range .Rows}}<div class="row"><span class="av{{if .Agent}} agent{{end}}">{{.Initials}}</span><div class="grow"><b>{{.Who}}</b>{{if .Agent}} <span class="pill agent">agent</span>{{end}} {{.Verb}}{{if .PRID}} <a href="/pull/{{.PRID}}">#{{.Number}} {{.PRTitle}}</a>{{end}}{{if .Detail}} <span class="muted small mono">{{.Detail}}</span>{{end}}</div><span class="meta">{{.When}}</span></div>{{else}}<div class="empty"><b>Nothing yet</b>Pull requests, comments, reviews, checks and deployments will appear here.</div>{{end}}</div>
</main>
<script>try{localStorage.setItem("secretree.activity.seen",String(Math.floor(Date.now()/1000)));var u=document.getElementById("unread");u.hidden=true}catch(e){}</script>
`))
