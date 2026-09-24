package app

import (
	"fmt"
	"html/template"
	"time"

	"github.com/buildsnap-dev/secretree/internal/collab"
	"github.com/buildsnap-dev/secretree/internal/config"
)

// chrome is what every page shows in its top bar: repository, proof
// badge, open pull request count. It is computed from local state only
// (no fetch) so pages stay fast; pages that need fresh data sync
// themselves.
type chrome struct {
	Repo, Source string
	Proof        string
	ProofOK      bool
	OpenPRs      int
	Kind         string // current section, for the tab strip
	Query, Ref   string
}

func (s *uiServer) chrome(kind string) chrome {
	c := chrome{Repo: s.name, Source: s.source, Kind: kind}
	c.Proof, c.ProofOK = s.proofBadge()
	if rp, err := s.app.openRepoAt(s.work, s.paths.Root+"/.."); err == nil {
		if vs, err := s.app.loadVaultLocal(rp); err == nil {
			store := s.app.collabStore(rp, vs)
			if events, _, err := store.Events(); err == nil {
				for _, pr := range collab.Fold(events) {
					if pr.State == collab.StateOpen {
						c.OpenPRs++
					}
				}
			}
		}
	}
	return c
}

// proofBadge summarises the restore proof for the header.
func (s *uiServer) proofBadge() (string, bool) {
	st, err := config.LoadStatus(s.paths)
	if err != nil || st == nil {
		return "", false
	}
	if st.LastProof == nil {
		if st.LastGeneration == 0 {
			return "no backup yet", false
		}
		return "restore not proven", false
	}
	d := time.Since(*st.LastProof).Round(time.Minute)
	txt := fmt.Sprintf("proven %s ago", d)
	if d < time.Minute {
		txt = "proven just now"
	}
	return txt, st.LastProofGeneration >= st.LastGeneration
}

// uiCSS is the design system of the local UI: the landing page's palette
// (paper and ink, a teal accent, gold for anything about ciphertext),
// system fonts, light and dark from the OS. No external resources.
const uiCSS = `<style>
:root{--bg:#F4F6F4;--bg2:#FFFFFF;--bg3:#E8ECE9;--fg:#141B1E;--fg2:#5B6965;--fg3:#8A9691;--line:#D3DAD6;--accent:#0E6B5E;--accent-fg:#FFFFFF;--accent-soft:#DCEFEA;--link:#0B5D52;
--gold:#8A6516;--gold-soft:#F5EBD1;--ok:#1F7A3A;--ok-soft:#DFF3E4;--bad:#B23B2E;--bad-soft:#F9E3E0;--warn:#9A6700;--warn-soft:#FFF3C4;--purple:#6B4FBB;--purple-soft:#E9E3F7;
--add:#E4F5E9;--del:#FBE7E4;--hunk:#E9F0F5;--hl:#FFF4C2;--kw:#9A3421;--str:#245E4F;--num:#1F5FA8;--cm:#7B8681;--shadow:0 1px 2px rgba(20,27,30,.06),0 1px 8px rgba(20,27,30,.04)}
@media (prefers-color-scheme: dark){:root{--bg:#0F1518;--bg2:#161D21;--bg3:#1E272C;--fg:#E4EAE6;--fg2:#A7B3AE;--fg3:#7C8985;--line:#2A3639;--accent:#5FC2A9;--accent-fg:#0F1518;--accent-soft:#1B3A34;--link:#8FDCC8;
--gold:#D2B15E;--gold-soft:#2B2410;--ok:#5CC17A;--ok-soft:#173224;--bad:#E5725F;--bad-soft:#3A1F1B;--warn:#D9A64B;--warn-soft:#332A12;--purple:#B79CF0;--purple-soft:#2A2340;
--add:#14301F;--del:#3A1A17;--hunk:#16232C;--hl:#3A3218;--kw:#FF8B7A;--str:#9BD9C6;--num:#8AB8FF;--cm:#7C8985;--shadow:none}}
*{box-sizing:border-box}
body{font:14px/1.5 -apple-system,"SF Pro Text",system-ui,"Segoe UI",sans-serif;margin:0;color:var(--fg);background:var(--bg)}
a{color:var(--link);text-decoration:none}a:hover{text-decoration:underline}
a:focus-visible,button:focus-visible,input:focus-visible,textarea:focus-visible,select:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
code,pre,.mono{font-family:ui-monospace,"SF Mono",SFMono-Regular,Menlo,Consolas,monospace}
code{background:var(--bg3);padding:1px 5px;border-radius:4px;font-size:12.5px}
/* top bar + tabs */
.top{background:var(--bg2);border-bottom:1px solid var(--line)}
.top .bar{max-width:1240px;margin:0 auto;padding:10px 20px;display:flex;align-items:center;gap:14px;flex-wrap:wrap}
.brand{display:flex;align-items:center;gap:8px;font-weight:600;color:var(--fg);font-size:15px}
.brand svg{width:20px;height:20px;color:var(--accent)}
.brand .src{color:var(--fg3);font-weight:400;font-size:12px;margin-left:4px}
.badge{font-size:12px;padding:3px 10px;border-radius:999px;border:1px solid var(--line);color:var(--fg2);background:var(--bg);white-space:nowrap;display:inline-flex;align-items:center;gap:6px}
.badge i{width:7px;height:7px;border-radius:50%;background:var(--fg3);display:inline-block}
.badge.ok{color:var(--ok);border-color:var(--ok)}.badge.ok i{background:var(--ok)}
.badge.warn{color:var(--warn);border-color:var(--warn)}.badge.warn i{background:var(--warn)}
.search{margin-left:auto;display:flex;align-items:center;gap:6px}
.search input{padding:6px 10px 6px 30px;border-radius:8px;border:1px solid var(--line);width:260px;background:var(--bg);color:var(--fg);font:inherit;background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='%238A9691' stroke-width='2'%3E%3Ccircle cx='11' cy='11' r='7'/%3E%3Cpath d='m20 20-3.5-3.5'/%3E%3C/svg%3E");background-repeat:no-repeat;background-size:15px;background-position:9px center}
.search kbd{font:11px ui-monospace,monospace;color:var(--fg3);border:1px solid var(--line);border-radius:4px;padding:1px 5px}
.tabs{max-width:1240px;margin:0 auto;padding:0 20px;display:flex;gap:2px;overflow-x:auto}
.tabs a{padding:8px 12px 10px;color:var(--fg2);border-bottom:2px solid transparent;display:flex;align-items:center;gap:7px;white-space:nowrap}
.tabs a:hover{color:var(--fg);text-decoration:none;border-color:var(--line)}
.tabs a.here{color:var(--fg);border-color:var(--accent);font-weight:600}
.tabs svg{width:16px;height:16px;opacity:.8}
.count{font-size:11px;background:var(--bg3);color:var(--fg2);border-radius:999px;padding:1px 7px;min-width:18px;text-align:center}
.count.new{background:var(--accent);color:var(--accent-fg)}
/* content */
main{max-width:1240px;margin:0 auto;padding:18px 20px 60px}
h1{font-size:22px;font-weight:600;margin:0 0 6px;letter-spacing:-.01em}
h2{font-size:17px;font-weight:600;margin:24px 0 10px}
h3{font-size:14px;font-weight:600;margin:0 0 8px;color:var(--fg2);text-transform:uppercase;letter-spacing:.06em;font-size:11.5px}
.lead{color:var(--fg2);margin:0 0 16px;max-width:70ch}
.card{background:var(--bg2);border:1px solid var(--line);border-radius:10px;box-shadow:var(--shadow)}
.card+.card{margin-top:12px}
.card .hd{padding:10px 14px;border-bottom:1px solid var(--line);display:flex;align-items:center;gap:10px;flex-wrap:wrap}
.card .hd b{font-weight:600}
.card .bd{padding:12px 14px}
.row{display:flex;align-items:center;gap:12px;padding:10px 14px;border-bottom:1px solid var(--line)}
.row:last-child{border-bottom:0}
.row .grow{flex:1;min-width:0}
.row .meta{color:var(--fg3);font-size:12.5px;white-space:nowrap}
.row .title{font-weight:600}
.stripe{width:4px;align-self:stretch;border-radius:2px;background:var(--line);flex:none}
.stripe.open{background:var(--ok)}.stripe.merged{background:var(--purple)}.stripe.closed{background:var(--bad)}
.empty{padding:36px 20px;text-align:center;color:var(--fg2)}.empty b{display:block;color:var(--fg);font-size:15px;margin-bottom:6px}
.empty code{font-size:12.5px}
.crumbs{display:flex;align-items:center;gap:6px;flex-wrap:wrap;margin-bottom:12px;font-size:14px}
.crumbs .sep{color:var(--fg3)}
.crumbs .tools{margin-left:auto;display:flex;gap:12px;font-size:13px}
.grid{display:grid;grid-template-columns:minmax(0,1fr) 300px;gap:18px;align-items:start}
@media (max-width:900px){.grid{grid-template-columns:1fr}.search input{width:180px}}
.side{position:sticky;top:12px}
.stat{display:flex;flex-direction:column;gap:2px;padding:6px 0}.stat b{font-size:20px;font-weight:600}.stat span{color:var(--fg2);font-size:12px}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:10px 18px}
/* pills */
.pill{display:inline-flex;align-items:center;gap:5px;padding:1px 9px;border-radius:999px;font-size:12px;font-weight:600;border:1px solid transparent}
.pill.open{background:var(--ok-soft);color:var(--ok)}.pill.merged{background:var(--purple-soft);color:var(--purple)}.pill.closed{background:var(--bad-soft);color:var(--bad)}
.pill.success{background:var(--ok-soft);color:var(--ok)}.pill.failure{background:var(--bad-soft);color:var(--bad)}.pill.pending{background:var(--warn-soft);color:var(--warn)}
.pill.agent{background:var(--purple-soft);color:var(--purple);font-size:11px}.pill.share{background:var(--purple-soft);color:var(--purple)}.pill.export{background:var(--warn-soft);color:var(--warn)}.pill.public-mirror{background:var(--bad-soft);color:var(--bad)}
.pill.approve{background:var(--ok-soft);color:var(--ok)}.pill.request_changes{background:var(--bad-soft);color:var(--bad)}.pill.comment{background:var(--bg3);color:var(--fg2)}
.who{display:inline-flex;align-items:center;gap:6px;font-weight:600}
.av{width:22px;height:22px;border-radius:50%;background:var(--accent-soft);color:var(--accent);display:inline-flex;align-items:center;justify-content:center;font-size:11px;font-weight:700;flex:none}
.av.agent{background:var(--purple-soft);color:var(--purple)}
/* code */
pre.code{margin:0;font:12.5px/1.6 ui-monospace,SFMono-Regular,Menlo,monospace;overflow:auto;background:var(--bg2)}
pre.code div{display:flex;white-space:pre}pre.code div:target{background:var(--hl)}
pre.code .n{width:56px;text-align:right;padding:0 10px;color:var(--fg3);user-select:none;flex:none}pre.code .n a{color:var(--fg3)}
pre.code .bl{width:210px;flex:none;color:var(--fg2);padding:0 10px;overflow:hidden;text-overflow:ellipsis;border-right:1px solid var(--line)}
pre.code .t{padding:0 12px}
.kw{color:var(--kw)}.str{color:var(--str)}.num{color:var(--num)}.cm{color:var(--cm);font-style:italic}
.diff{font:12.5px/1.6 ui-monospace,SFMono-Regular,Menlo,monospace;overflow:auto;background:var(--bg2)}
.diff div{white-space:pre;padding:0 12px}.diff .a{background:var(--add)}.diff .d{background:var(--del)}.diff .k{color:var(--link);background:var(--hunk)}.diff .f{font-weight:600;background:var(--bg3);padding:6px 12px;position:sticky;top:0}.diff .h{color:var(--fg3)}
.diff.rows div{display:flex;align-items:flex-start;padding:0}.diff.rows .ln{width:48px;flex:none;text-align:right;padding-right:8px;color:var(--fg3);user-select:none}.diff.rows .tx{padding-left:10px;white-space:pre;flex:1}
.diff.rows .add{width:20px;flex:none;text-align:center;color:transparent;font-weight:700;border-radius:4px}.diff.rows div:hover .add{color:var(--accent-fg);background:var(--accent)}
.diff.rows .ic{display:block;white-space:normal;background:var(--bg);border-top:1px solid var(--line);border-bottom:1px solid var(--line);padding:8px 12px 8px 78px;font:13px/1.5 -apple-system,system-ui,sans-serif}
.diff.rows form.ic textarea{min-height:64px}
.md p{margin:0 0 8px}.md p:last-child{margin:0}.md pre{background:var(--bg3);padding:8px 10px;border-radius:6px;overflow:auto;font-size:12px}.md code{font-size:12px}.md ul,.md ol{margin:0 0 8px;padding-left:20px}.md blockquote{margin:0 0 8px;padding-left:10px;border-left:3px solid var(--line);color:var(--fg2)}
.sha{font-family:ui-monospace,Menlo,monospace;color:var(--fg2);font-size:12.5px}
.muted{color:var(--fg2)}.small{font-size:12.5px}
/* forms */
textarea,input[type=text],select{width:100%;padding:7px 9px;font:inherit;background:var(--bg2);color:var(--fg);border:1px solid var(--line);border-radius:8px}textarea{min-height:76px;resize:vertical}
button,.btn{padding:6px 14px;font:inherit;font-weight:600;background:var(--bg2);color:var(--fg);border:1px solid var(--line);border-radius:8px;cursor:pointer;display:inline-flex;align-items:center;gap:6px}
button:hover,.btn:hover{background:var(--bg3);text-decoration:none}
button.primary{background:var(--accent);color:var(--accent-fg);border-color:var(--accent)}button.primary:hover{filter:brightness(1.08)}
button.danger{background:var(--bad);color:#fff;border-color:var(--bad)}button:disabled{opacity:.45;cursor:default;filter:none}
button.small{padding:2px 9px;font-size:12px;font-weight:500}
form.inline{display:inline}.actions{display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-top:8px}
.err{background:var(--bad-soft);border:1px solid var(--bad);color:var(--fg);padding:10px 12px;border-radius:8px;margin-bottom:12px}
.block{background:var(--warn-soft);border:1px solid var(--warn);padding:10px 12px;border-radius:8px}
.note{background:var(--gold-soft);border:1px solid var(--gold);color:var(--fg);padding:10px 12px;border-radius:8px}
details summary{cursor:pointer;color:var(--fg2)}pre.log{font:11.5px/1.45 ui-monospace,Menlo,monospace;background:var(--bg3);padding:8px 10px;border-radius:6px;overflow:auto;max-height:320px}
/* timeline */
.tl{position:relative;padding-left:26px}.tl:before{content:"";position:absolute;left:10px;top:6px;bottom:6px;width:2px;background:var(--line)}
.ev{position:relative;margin:0 0 12px}.ev:before{content:"";position:absolute;left:-21px;top:8px;width:10px;height:10px;border-radius:50%;background:var(--bg);border:2px solid var(--line)}
.ev.approve:before{border-color:var(--ok);background:var(--ok)}.ev.request_changes:before{border-color:var(--bad);background:var(--bad)}.ev.merged:before{border-color:var(--purple);background:var(--purple)}
.ev .hd{display:flex;align-items:center;gap:8px;flex-wrap:wrap;font-size:13px;color:var(--fg2);margin-bottom:4px}
.ev .body{background:var(--bg2);border:1px solid var(--line);border-radius:8px;padding:8px 12px}
.ev.done{opacity:.65}
.cipher{font-family:ui-monospace,Menlo,monospace;font-size:12px;color:var(--gold)}
table{border-collapse:collapse;width:100%}td,th{padding:7px 10px;text-align:left;border-bottom:1px solid var(--line);vertical-align:top}th{font-size:11.5px;color:var(--fg2);font-weight:600;text-transform:uppercase;letter-spacing:.05em}tr:last-child td{border-bottom:0}
.tree a.dir{font-weight:600}
.ico{width:16px;height:16px;vertical-align:-3px;margin-right:6px;color:var(--fg3)}
</style>
`

// icons are inline SVG paths (stroke-based, 24-unit grid).
const icoCode = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m16 18 6-6-6-6M8 6l-6 6 6 6"/></svg>`
const icoPR = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="18" cy="18" r="3"/><circle cx="6" cy="6" r="3"/><path d="M13 6h3a2 2 0 0 1 2 2v7M6 9v12"/></svg>`
const icoActivity = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 12h-4l-3 9L9 3l-3 9H2"/></svg>`
const icoLedger = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 19.5A2.5 2.5 0 0 1 6.5 17H20M4 19.5V4.5A2.5 2.5 0 0 1 6.5 2H20v20H6.5a2.5 2.5 0 0 1-2.5-2.5z"/></svg>`
const icoVault = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>`
const icoTree = `<svg class="ico" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/></svg>`
const icoFile = `<svg class="ico" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6"/></svg>`
const icoBrand = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3v18M12 3l-5 5M12 3l5 5M12 12l-4-4M12 12l4-4M12 21l-6-6M12 21l6-6"/></svg>`

// uiHeader is the top bar and tab strip shared by every page. The page
// value must embed chrome.
const uiHeader = `<div class="top"><div class="bar">
<a class="brand" href="/">` + icoBrand + `{{.Repo}}<span class="src">{{.Source}}</span></a>
{{if .Proof}}<a href="/vault" class="badge {{if .ProofOK}}ok{{else}}warn{{end}}" title="restore proof"><i></i>{{.Proof}}</a>{{end}}
<form class="search" action="/search"><input id="q" name="q" placeholder="Search code" value="{{.Query}}" autocomplete="off"><input type="hidden" name="ref" value="{{if .Ref}}{{.Ref}}{{else}}HEAD{{end}}"><kbd>/</kbd></form>
</div>
<nav class="tabs">
<a href="/" class="{{if eq .Kind "home" "tree" "blob" "commits" "commit" "search"}}here{{end}}">` + icoCode + `Code</a>
<a href="/pulls" class="{{if eq .Kind "list" "pr" "new"}}here{{end}}">` + icoPR + `Pull requests{{if .OpenPRs}} <span class="count">{{.OpenPRs}}</span>{{end}}</a>
<a href="/activity" class="{{if eq .Kind "activity"}}here{{end}}">` + icoActivity + `Activity <span class="count" id="unread" hidden></span></a>
<a href="/ledger" class="{{if eq .Kind "ledger"}}here{{end}}">` + icoLedger + `Ledger</a>
<a href="/vault" class="{{if eq .Kind "vault"}}here{{end}}">` + icoVault + `Vault</a>
</nav></div>
<script>
document.addEventListener("keydown",function(e){if(e.key==="/"&&!/input|textarea|select/i.test(e.target.tagName)){e.preventDefault();document.getElementById("q").focus()}});
(function(){try{var seen=+localStorage.getItem("secretree.activity.seen")||0;var el=document.getElementById("unread");var xhr=new XMLHttpRequest();xhr.open("GET","/activity.json?since="+seen);xhr.onload=function(){try{var n=JSON.parse(xhr.responseText).count;if(n>0){el.textContent=n;el.className="count new";el.hidden=false}}catch(e){}};xhr.send()}catch(e){}})();
</script>`

var _ = template.HTMLEscapeString
