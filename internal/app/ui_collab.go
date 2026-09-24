package app

import (
	"crypto/rand"
	"encoding/hex"
	"html/template"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/buildsnap-dev/secretree/internal/collab"
	"github.com/buildsnap-dev/secretree/internal/gitx"
)

func newToken() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func (s *uiServer) collabRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /pulls", s.pulls)
	mux.HandleFunc("GET /pulls/new", s.pullNew)
	mux.HandleFunc("POST /pulls/new", s.pullNew)
	mux.HandleFunc("GET /pull/{id}", s.pull)
	mux.HandleFunc("POST /pull/{id}/comment", s.pullAction)
	mux.HandleFunc("POST /pull/{id}/review", s.pullAction)
	mux.HandleFunc("POST /pull/{id}/merge", s.pullAction)
	mux.HandleFunc("POST /pull/{id}/close", s.pullAction)
	mux.HandleFunc("POST /pull/{id}/resolve", s.pullAction)
}

// quiet returns an App whose output is discarded (UI actions report via redirects).
func (s *uiServer) quiet() *App { return &App{Out: io.Discard, Err: io.Discard} }

func (s *uiServer) checkCSRF(w http.ResponseWriter, r *http.Request) bool {
	if r.FormValue("csrf") != s.csrf {
		http.Error(w, "bad csrf token; reload the page", http.StatusForbidden)
		return false
	}
	return true
}

type prRow struct {
	ID, Title, Head, Base, Author, State, Date string
	Initials                                   string
	Comments                                   int
	Number                                     int
	Approved, Changes                          []string
	Checks                                     []checkRow
}

type checkRow struct{ Name, Status, Summary, Log string }

type prPage struct {
	chrome
	Title, CSRF, Error string
	All                bool
	Rows               []prRow
	PR                 *prRow
	Body               string
	BodyHTML           template.HTML
	HeadSHA, BaseSHA   string
	Diff               template.HTML
	DiffRows           []diffRow
	Events             []eventRow
	Policy             collab.Policy
	MergeBlock         string
	Branches           []string
	Files              int
}

type eventRow struct {
	ID, Kind, Who, When, Body, Path, Verdict, State, Commit string
	Initials                                                string
	BodyHTML                                                template.HTML
	Line                                                    int
	Agent                                                   bool   // written by an agent member
	ResolvedBy                                              string // thread resolved, by whom
	Moved                                                   bool   // followed to a new line on the current head
	Outdated                                                bool   // its line changed since; not shown inline
}

func (s *uiServer) renderPR(w http.ResponseWriter, p *prPage) {
	kind := p.Kind
	p.chrome = s.chrome(kind)
	p.Kind, p.CSRF = kind, s.csrf
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", uiCSP)
	if err := prTmpl.Execute(w, p); err != nil {
		http.Error(w, err.Error(), 500)
	}
}

func (s *uiServer) row(c *prContext, pr *collab.PullRequest) prRow {
	head := c.headSHA(pr)
	approved, changes := pr.Approvals(head)
	row := prRow{ID: pr.ID, Number: pr.Number, Title: pr.Title, Head: pr.Head, Base: pr.Base, Author: pr.Author, State: pr.State,
		Date: pr.Created.Format("2006-01-02"), Approved: approved, Changes: changes, Initials: initials(pr.Author)}
	for _, e := range pr.Events {
		if e.Kind == collab.KindComment {
			row.Comments++
		}
	}
	for name, e := range collab.Checks(c.events, head) {
		row.Checks = append(row.Checks, checkRow{Name: name, Status: e.Status, Summary: e.Summary, Log: e.Log})
	}
	return row
}

func (s *uiServer) pulls(w http.ResponseWriter, r *http.Request) {
	c, err := s.app.openPR(s.work)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	p := &prPage{chrome: chrome{Kind: "list"}, Title: "pull requests", All: r.URL.Query().Get("all") == "1"}
	open := 0
	for i := range c.prs {
		if c.prs[i].State == collab.StateOpen {
			open++
		}
	}
	// an empty "open" list next to merged work is confusing: fall back to all
	if open == 0 && len(c.prs) > 0 && !p.All {
		p.All = true
		p.Error = ""
		p.Body = "no open pull requests; showing merged and closed ones"
	}
	for i := range c.prs {
		if !p.All && c.prs[i].State != collab.StateOpen {
			continue
		}
		p.Rows = append(p.Rows, s.row(c, &c.prs[i]))
	}
	if len(c.prs) == 0 {
		p.Body = "no pull requests yet: push a branch and open one here, or with secretree pr open"
	}
	s.renderPR(w, p)
}

func (s *uiServer) pull(w http.ResponseWriter, r *http.Request) {
	c, err := s.app.openPR(s.work)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	pr, err := collab.Resolve(c.prs, r.PathValue("id"))
	if err != nil {
		http.Error(w, err.Error(), 404)
		return
	}
	row := s.row(c, pr)
	head, base := c.headSHA(pr), c.baseSHA(pr)
	p := &prPage{chrome: chrome{Kind: "pr"}, Title: "#" + strconv.Itoa(pr.Number) + " " + pr.Title, PR: &row, Body: pr.Body, BodyHTML: md(pr.Body), HeadSHA: head, BaseSHA: base,
		Policy: collab.LoadPolicy(c.r.Work, base), Error: r.URL.Query().Get("error")}
	if pr.State == collab.StateOpen {
		p.MergeBlock = c.mergeCheck(pr, head, base)
		if out, err := gitx.Run(c.r.Work, "diff", base+"..."+head); err == nil {
			p.DiffRows = parseDiff(out, inlineComments(c, pr, head))
			p.Files = strings.Count(out, "\ndiff --git ") + boolInt(strings.HasPrefix(out, "diff --git "))
		}
	} else if pr.MergeCommit != "" {
		if out, err := gitx.Run(c.r.Work, "show", "--stat", "--format=merged as %h", pr.MergeCommit); err == nil {
			p.Diff = renderDiff(out)
		}
	}
	resolved := pr.Resolved()
	for _, e := range pr.Events {
		who := e.ActorName
		if who == "" {
			who = e.Actor
		}
		row := eventRow{ID: e.ID, Kind: e.Kind, Who: who, Initials: initials(who), When: e.Created.Format("2006-01-02 15:04"), Body: e.Body, BodyHTML: md(e.Body),
			Path: e.Path, Line: e.Line, Verdict: e.Verdict, State: e.State, Commit: short(e.Commit), Agent: c.agents[e.Actor], ResolvedBy: resolved[e.ID]}
		if e.Kind == collab.KindComment && e.Path != "" && e.Commit != "" && e.Commit != head {
			if _, ok := remapLine(c.r.Work, e.Commit, head, e.Path, e.Line); !ok {
				row.Outdated = true
			}
		}
		p.Events = append(p.Events, row)
	}
	s.renderPR(w, p)
}

func (s *uiServer) pullNew(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		if !s.checkCSRF(w, r) {
			return
		}
		err := s.quiet().PROpen(PROpenOptions{Dir: s.work, Title: r.FormValue("title"), Body: r.FormValue("body"), Head: r.FormValue("head"), Base: r.FormValue("base")})
		if err != nil {
			http.Redirect(w, r, "/pulls/new?error="+template.URLQueryEscaper(err.Error()), http.StatusSeeOther)
			return
		}
		http.Redirect(w, r, "/pulls", http.StatusSeeOther)
		return
	}
	p := &prPage{chrome: chrome{Kind: "new"}, Title: "new pull request", Error: r.URL.Query().Get("error")}
	remote := secretreeRemote(s.work)
	pattern := "refs/heads/"
	if remote != "" {
		pattern = "refs/remotes/" + remote + "/"
	}
	if out, err := gitx.Run(s.work, "for-each-ref", "--format=%(refname:short)", pattern); err == nil {
		for _, b := range strings.Fields(out) {
			b = strings.TrimPrefix(b, remote+"/")
			if b != "HEAD" {
				p.Branches = append(p.Branches, b)
			}
		}
	}
	s.renderPR(w, p)
}

func (s *uiServer) pullAction(w http.ResponseWriter, r *http.Request) {
	if !s.checkCSRF(w, r) {
		return
	}
	id := r.PathValue("id")
	action := r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:]
	a := s.quiet()
	var err error
	switch action {
	case "comment":
		line, _ := strconv.Atoi(r.FormValue("line"))
		err = a.PRComment(s.work, id, r.FormValue("body"), r.FormValue("path"), line)
	case "review":
		err = a.PRReview(s.work, id, r.FormValue("verdict"), r.FormValue("body"))
	case "merge":
		err = a.PRMerge(s.work, id, r.FormValue("method"))
	case "close":
		err = a.PRClose(s.work, id)
	case "resolve":
		err = a.PRResolve(s.work, id, r.FormValue("comment"))
	}
	target := "/pull/" + id
	if err != nil {
		target += "?error=" + template.URLQueryEscaper(err.Error())
	}
	http.Redirect(w, r, target, http.StatusSeeOther)
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// initials picks up to two letters for an avatar circle.
func initials(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return "?"
	}
	parts := strings.FieldsFunc(name, func(r rune) bool { return r == ' ' || r == '-' || r == '_' || r == '.' })
	out := ""
	for _, p := range parts {
		if p != "" {
			out += strings.ToUpper(p[:1])
		}
		if len(out) == 2 {
			break
		}
	}
	return out
}

var prTmpl = template.Must(template.New("pr").Parse(`<!doctype html>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{{.Repo}}: {{.Title}}</title>
` + uiCSS + uiHeader + `
<main>
{{if .Error}}<div class="err">{{.Error}}</div>{{end}}

{{if eq .Kind "list"}}
<div style="display:flex;align-items:center;gap:12px;margin-bottom:12px;flex-wrap:wrap">
<h1 style="margin:0">Pull requests</h1>
<span class="muted small">{{if .All}}<a href="/pulls">open only</a>{{else}}<a href="/pulls?all=1">show merged and closed</a>{{end}}</span>
<a class="btn" href="/pulls/new" style="margin-left:auto">New pull request</a>
</div>
<div class="card">
{{range .Rows}}<div class="row"><span class="stripe {{.State}}"></span>
<div class="grow"><a class="title" href="/pull/{{.ID}}">{{.Title}}</a> <span class="muted small">#{{.Number}}</span>
<div class="small muted">{{.Head}} → {{.Base}} · <span class="who"><span class="av">{{.Initials}}</span>{{.Author}}</span> · {{.Date}}{{if .Comments}} · {{.Comments}} comment{{if ne .Comments 1}}s{{end}}{{end}}</div></div>
<div style="display:flex;gap:6px;flex-wrap:wrap;justify-content:flex-end">{{range .Approved}}<span class="pill success">✓ {{.}}</span>{{end}}{{range .Changes}}<span class="pill failure">✗ {{.}}</span>{{end}}{{range .Checks}}<span class="pill {{.Status}}" title="{{.Summary}}">{{.Name}}</span>{{end}}<span class="pill {{.State}}">{{.State}}</span></div></div>
{{else}}<div class="empty"><b>{{if .All}}No pull requests yet{{else}}No open pull requests{{end}}</b>{{if .Body}}{{.Body}}{{else}}Push a branch, then open one here or with <code>secretree pr open --title "…"</code>.{{end}}</div>{{end}}
</div>
{{end}}

{{if eq .Kind "new"}}
<h1>New pull request</h1>
<form method="post" action="/pulls/new" class="card"><div class="bd"><input type="hidden" name="csrf" value="{{.CSRF}}">
<div class="grid" style="grid-template-columns:1fr 1fr;gap:12px"><div><h3>Head (your branch)</h3><select name="head">{{range .Branches}}<option>{{.}}</option>{{end}}</select></div>
<div><h3>Base</h3><select name="base">{{range .Branches}}<option {{if eq . "main"}}selected{{end}}>{{.}}</option>{{end}}</select></div></div>
<h3 style="margin-top:14px">Title</h3><input type="text" name="title" required>
<h3 style="margin-top:14px">Description</h3><textarea name="body" placeholder="Markdown is fine"></textarea>
<div class="actions"><button class="primary">Open pull request</button><a class="btn" href="/pulls">Cancel</a></div></div></form>
{{end}}

{{if eq .Kind "pr"}}
<div style="margin-bottom:14px"><h1><span class="muted" style="font-weight:400">#{{.PR.Number}}</span> {{.PR.Title}} <span class="pill {{.PR.State}}">{{.PR.State}}</span></h1>
<div class="muted small"><span class="who"><span class="av">{{.PR.Initials}}</span>{{.PR.Author}}</span> wants to merge <code>{{.PR.Head}}</code> <span class="sha">{{slice .HeadSHA 0 8}}</span> into <code>{{.PR.Base}}</code> <span class="sha">{{slice .BaseSHA 0 8}}</span> · opened {{.PR.Date}}{{if .Files}} · {{.Files}} file{{if ne .Files 1}}s{{end}} changed{{end}}</div></div>
<div class="grid">
<div>
{{if .Body}}<div class="card"><div class="bd md">{{.BodyHTML}}</div></div>{{end}}
<h2>Changes</h2>
<div class="card">{{if .DiffRows}}<div class="diff rows">{{range $i,$r := .DiffRows}}<div class="{{$r.Class}}"{{if $r.NewLine}} id="{{$r.Path}}-L{{$r.NewLine}}"{{end}}>{{if $r.NewLine}}<a class="add" href="#" data-path="{{$r.Path}}" data-line="{{$r.NewLine}}" title="Comment on {{$r.Path}}:{{$r.NewLine}}">+</a><span class="ln">{{$r.NewLine}}</span>{{else}}<span class="add"></span><span class="ln"></span>{{end}}<span class="tx">{{$r.Text}}</span></div>{{range $r.Comments}}<div class="ic{{if .ResolvedBy}} done{{end}}"><span class="who"><span class="av{{if .Agent}} agent{{end}}">{{.Initials}}</span>{{.Who}}</span>{{if .Agent}} <span class="pill agent">agent</span>{{end}} <span class="muted small">{{.When}}{{if .Moved}} · followed from line {{.Line}} of {{.Commit}}{{end}}</span>
{{if .ResolvedBy}}<span class="muted small"> · resolved by {{.ResolvedBy}}</span><details><summary>show</summary><div class="md">{{.BodyHTML}}</div></details>{{else}}<div class="md" style="margin-top:4px">{{.BodyHTML}}</div><form method="post" action="/pull/{{$.PR.ID}}/resolve" class="inline"><input type="hidden" name="csrf" value="{{$.CSRF}}"><input type="hidden" name="comment" value="{{.ID}}"><button class="small">Resolve</button></form>{{end}}</div>{{end}}{{end}}</div>
{{else if .Diff}}<div class="diff">{{.Diff}}</div>{{else}}<div class="empty"><b>No changes</b></div>{{end}}</div>

<h2>Conversation</h2>
<div class="tl">
{{range .Events}}{{if eq .Kind "comment"}}<div class="ev{{if .ResolvedBy}} done{{end}}"><div class="hd"><span class="who"><span class="av{{if .Agent}} agent{{end}}">{{.Initials}}</span>{{.Who}}</span>{{if .Agent}}<span class="pill agent">agent</span>{{end}}<span>{{.When}}</span>{{if .Path}}<a class="mono small" href="#{{.Path}}-L{{.Line}}">{{.Path}}:{{.Line}}</a>{{if .Outdated}}<span class="pill comment">outdated</span>{{end}}{{end}}{{if .ResolvedBy}}<span class="pill comment">resolved by {{.ResolvedBy}}</span>{{end}}</div><div class="body md">{{.BodyHTML}}</div></div>
{{else if eq .Kind "review"}}<div class="ev {{.Verdict}}"><div class="hd"><span class="who"><span class="av{{if .Agent}} agent{{end}}">{{.Initials}}</span>{{.Who}}</span>{{if .Agent}}<span class="pill agent">agent</span>{{end}}<span class="pill {{.Verdict}}">{{if eq .Verdict "approve"}}approved{{else if eq .Verdict "request_changes"}}requested changes{{else}}commented{{end}}</span><span>{{.When}} · <span class="sha">{{.Commit}}</span></span></div>{{if .Body}}<div class="body md">{{.BodyHTML}}</div>{{end}}</div>
{{else if eq .Kind "state"}}<div class="ev {{.State}}"><div class="hd"><span class="who"><span class="av">{{.Initials}}</span>{{.Who}}</span><span>{{if eq .State "merged"}}merged this{{else}}closed this{{end}} · {{.When}}{{if .Commit}} · <span class="sha">{{.Commit}}</span>{{end}}</span></div></div>{{end}}{{end}}
</div>
{{if eq .PR.State "open"}}
<div class="grid" style="grid-template-columns:1fr 1fr;gap:12px;margin-top:8px">
<form method="post" action="/pull/{{.PR.ID}}/comment" class="card"><div class="bd"><input type="hidden" name="csrf" value="{{.CSRF}}"><h3>Comment</h3>
<textarea name="body" required placeholder="Markdown is fine. Use the + next to a diff line for a line comment."></textarea>
<div class="actions"><button>Comment</button></div></div></form>
<form method="post" action="/pull/{{.PR.ID}}/review" class="card"><div class="bd"><input type="hidden" name="csrf" value="{{.CSRF}}"><h3>Review <span class="sha">{{slice .HeadSHA 0 8}}</span></h3>
<textarea name="body" placeholder="Summary (optional)"></textarea>
<div class="actions"><select name="verdict" style="width:auto"><option value="approve">Approve</option><option value="request_changes">Request changes</option><option value="comment">Comment only</option></select><button class="primary">Submit review</button></div></div></form>
</div>
{{end}}
</div>

<div class="side">
<div class="card"><div class="hd"><b>Reviews</b><span class="muted small">policy: {{.Policy.RequiredApprovals}} approval{{if ne .Policy.RequiredApprovals 1}}s{{end}}{{range .Policy.RequiredChecks}}, {{.}}{{end}}</span></div><div class="bd">
{{range .PR.Approved}}<div><span class="pill success">✓ {{.}}</span></div>{{end}}{{range .PR.Changes}}<div><span class="pill failure">✗ {{.}}</span></div>{{end}}{{if and (not .PR.Approved) (not .PR.Changes)}}<span class="muted small">No reviews of the current head yet.</span>{{end}}</div></div>
<div class="card"><div class="hd"><b>Checks</b></div><div class="bd">{{range .PR.Checks}}<div style="margin-bottom:6px"><span class="pill {{.Status}}">{{.Name}}</span> <span class="muted small">{{.Summary}}</span>{{if .Log}}<details><summary class="small">log</summary><pre class="log">{{.Log}}</pre></details>{{end}}</div>{{else}}<span class="muted small">No checks yet. A runner records one per commit: <code>secretree runner</code>.</span>{{end}}</div></div>
{{if eq .PR.State "open"}}
<div class="card"><div class="bd">{{if .MergeBlock}}<div class="block small">{{.MergeBlock}}</div>{{else}}<div class="small" style="color:var(--ok);font-weight:600">Ready to merge</div>{{end}}
<form method="post" action="/pull/{{.PR.ID}}/merge" class="actions"><input type="hidden" name="csrf" value="{{.CSRF}}">
<select name="method" style="width:auto"><option value="merge">Merge commit</option><option value="squash">Squash</option><option value="ff">Fast-forward</option></select>
<button class="primary" {{if .MergeBlock}}disabled{{end}}>Merge</button></form>
<form method="post" action="/pull/{{.PR.ID}}/close" class="actions"><input type="hidden" name="csrf" value="{{.CSRF}}"><button class="small">Close without merging</button></form></div></div>
{{end}}
<div class="card"><div class="bd small muted">On the command line:<br><code>secretree pr checkout {{.PR.Number}}</code><br><code>secretree pr diff {{.PR.Number}}</code></div></div>
</div>
</div>
{{end}}
</main>
<script>
document.addEventListener("click", function (ev) {
  var a = ev.target.closest && ev.target.closest("a.add"); if (!a) return;
  ev.preventDefault();
  var row = a.parentNode; var existing = row.nextElementSibling;
  if (existing && existing.tagName === "FORM") { existing.remove(); return; }
  var f = document.createElement("form"); f.method = "post"; f.className = "ic";
  f.action = location.pathname.replace(/\/$/, "") + "/comment";
  f.innerHTML = '<input type="hidden" name="csrf" value="' + document.querySelector('input[name=csrf]').value + '">' +
    '<input type="hidden" name="path" value="' + a.dataset.path.replace(/"/g, "&quot;") + '"><input type="hidden" name="line" value="' + a.dataset.line + '">' +
    '<div class="muted small" style="margin-bottom:4px">' + a.dataset.path + ':' + a.dataset.line + '</div><textarea name="body" required placeholder="Comment on this line"></textarea><div class="actions"><button class="primary small">Comment</button> <button type="button" class="small cancel">Cancel</button></div>';
  f.querySelector(".cancel").onclick = function () { f.remove(); };
  row.insertAdjacentElement("afterend", f); f.querySelector("textarea").focus();
});
if(location.hash&&self===top){var e=document.getElementById(location.hash.slice(1));e&&e.scrollIntoView({block:"center"})}
</script>
`))
