package app

import (
	"html/template"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/buildsnap-dev/secretree/internal/config"
	"github.com/buildsnap-dev/secretree/internal/gitx"
	"github.com/buildsnap-dev/secretree/internal/vault"
)

// ledgerRow and vaultPage feed the two "why trust this" pages.
type ledgerRow struct {
	Seq                        int
	When, Kind, Subject, Actor string
	Note, Expires              string
	Expired                    bool
}

type genRow struct {
	Num        int
	Kind, When string
	Refs       int
	Size       string
	Opaque     bool
}

type hostFile struct {
	Path string
	Size string
}

type vaultPage struct {
	chrome
	Title      string
	Ledger     []ledgerRow
	Gens       []genRow
	Files      []hostFile
	Meta       string
	VaultURL   string
	VaultID    string
	Members    int
	Signers    int
	TotalSize  string
	LastBackup string
	LastProof  string
	KitPending bool
}

func (s *uiServer) ledger(w http.ResponseWriter, r *http.Request) {
	rp, err := s.app.openRepo(s.work)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	vs, err := s.app.loadVault(rp)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	entries, _, err := loadLedger(rp, vs)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	p := &vaultPage{chrome: chrome{Kind: "ledger"}, Title: "disclosure ledger"}
	for i := len(entries) - 1; i >= 0; i-- {
		e := entries[i]
		row := ledgerRow{Seq: e.Seq, When: e.Created.Format("2006-01-02 15:04"), Kind: e.Kind, Subject: e.Subject, Actor: e.ActorName, Note: e.Note}
		if row.Actor == "" {
			row.Actor = e.Actor
		}
		if e.Expires != nil {
			row.Expires = e.Expires.Format("2006-01-02")
			row.Expired = time.Now().After(*e.Expires)
		}
		p.Ledger = append(p.Ledger, row)
	}
	s.renderVault(w, p)
}

func (s *uiServer) vault(w http.ResponseWriter, r *http.Request) {
	rp, err := s.app.openRepo(s.work)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	vs, err := s.app.loadVault(rp)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	p := &vaultPage{chrome: chrome{Kind: "vault"}, Title: "vault", VaultURL: rp.Cfg.VaultURL, VaultID: vs.Meta.VaultID,
		Members: len(vs.Meta.Recipients), Signers: len(vs.Signers.Active), TotalSize: humanBytes(vs.Chain.Bytes())}
	for _, g := range vs.Chain.Gens {
		row := genRow{Num: g.Num, Opaque: g.Opaque()}
		if !g.Opaque() {
			var size int64
			for _, f := range g.Manifest.Files {
				size += f.Size
			}
			row.Kind, row.When, row.Refs, row.Size = g.Manifest.Kind, g.Manifest.Created.Format("2006-01-02 15:04"), len(g.Manifest.Refs), humanBytes(size)
		}
		p.Gens = append(p.Gens, row)
	}
	sort.Slice(p.Gens, func(i, j int) bool { return p.Gens[i].Num > p.Gens[j].Num })
	if out, err := gitx.Run(rp.Paths.Cache, "ls-tree", "-r", "-l", "HEAD"); err == nil {
		for _, l := range strings.Split(strings.TrimSpace(out), "\n") {
			meta, name, ok := strings.Cut(l, "\t")
			if !ok {
				continue
			}
			f := strings.Fields(meta)
			size := ""
			if len(f) == 4 {
				if n, err := strconv.ParseInt(f[3], 10, 64); err == nil {
					size = humanBytes(n)
				}
			}
			p.Files = append(p.Files, hostFile{Path: name, Size: size})
		}
	}
	if raw, err := vs.Reader.ReadFile(vault.MetaFile); err == nil {
		p.Meta = string(raw)
	}
	if st, err := config.LoadStatus(rp.Paths); err == nil {
		p.LastBackup = agoShort(st.LastBackup)
		p.LastProof = agoShort(st.LastProof)
		p.KitPending = st.KitPending && st.KitConfirmed == nil
	}
	s.renderVault(w, p)
}

func (s *uiServer) renderVault(w http.ResponseWriter, p *vaultPage) {
	kind := p.Kind
	p.chrome = s.chrome(kind)
	p.Kind = kind
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", uiCSP)
	if err := vaultTmpl.Execute(w, p); err != nil {
		http.Error(w, err.Error(), 500)
	}
}

var vaultTmpl = template.Must(template.New("vault").Parse(`<!doctype html>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{{.Repo}}: {{.Title}}</title>
` + uiCSS + `<style>pre.meta{background:var(--bg3);border-radius:8px;padding:10px 12px;font-size:12px;overflow:auto;margin:0}.expired{color:var(--fg3);text-decoration:line-through}</style>
` + uiHeader + `
<main>
{{if eq .Kind "ledger"}}
<h1>Disclosure ledger</h1>
<p class="lead">Everything that ever left the key boundary on purpose: share pages, exports to services, public mirrors. Each entry is encrypted to the members, signed by the device that made it and hash-chained to the previous one, so the list can be neither forged nor silently trimmed.</p>
<div class="card">{{if .Ledger}}<table><tr><th>#</th><th>when</th><th>kind</th><th>what left</th><th>by</th><th>expires</th><th>why</th></tr>
{{range .Ledger}}<tr><td class="muted">{{printf "%06d" .Seq}}</td><td>{{.When}}</td><td><span class="pill {{.Kind}}">{{.Kind}}</span></td><td class="cipher">{{.Subject}}</td><td>{{.Actor}}</td><td{{if .Expired}} class="expired"{{end}}>{{.Expires}}</td><td class="muted">{{.Note}}</td></tr>{{end}}</table>
{{else}}<div class="empty"><b>Nothing has left the vault in plaintext</b>No share pages, no exports. When a member runs <code>secretree share</code> or an agent sends a diff to a model, it is listed here.</div>{{end}}</div>
{{end}}

{{if eq .Kind "vault"}}
<h1>The vault as the host sees it</h1>
<p class="lead">{{.VaultURL}} · vault id <span class="mono">{{.VaultID}}</span></p>
{{if .KitPending}}<div class="note" style="margin-bottom:14px">The recovery kit of this vault has not been confirmed as printed. Without it a lost machine means lost backups. <code>secretree kit --html</code>, print, then <code>secretree kit --confirm</code>.</div>{{end}}
<div class="card"><div class="bd stats">
<div class="stat"><b>{{len .Gens}}</b><span>generations</span></div>
<div class="stat"><b>{{.TotalSize}}</b><span>ciphertext on the remote</span></div>
<div class="stat"><b>{{.Members}}</b><span>recipients</span></div>
<div class="stat"><b>{{.Signers}}</b><span>signers</span></div>
<div class="stat"><b>{{.LastBackup}}</b><span>last backup</span></div>
<div class="stat"><b>{{.LastProof}}</b><span>last restore proof</span></div>
</div></div>
<div class="grid" style="grid-template-columns:1fr 1fr;margin-top:14px">
<div>
<h2>Files on the remote</h2>
<p class="muted small">Real listing of the vault repository. Nothing here is readable without a member's key; the names carry only generation numbers.</p>
<div class="card"><table><tr><th>path</th><th>size</th></tr>{{range .Files}}<tr><td class="cipher">{{.Path}}</td><td class="muted" style="white-space:nowrap">{{.Size}}</td></tr>{{end}}</table></div>
</div>
<div>
<h2>Generations</h2>
<div class="card"><table><tr><th>#</th><th>kind</th><th>written</th><th>refs</th><th>size</th></tr>
{{range .Gens}}<tr><td class="muted">{{printf "%06d" .Num}}</td>{{if .Opaque}}<td colspan="4" class="muted">opaque: written before this key was a member (signature and chain verified)</td>{{else}}<td>{{.Kind}}</td><td>{{.When}}</td><td>{{.Refs}}</td><td class="muted">{{.Size}}</td>{{end}}</tr>{{end}}</table></div>
<h2>vault.json</h2>
<p class="muted small">The only plaintext metadata: public keys of recipients and signers.</p>
<div class="card"><pre class="meta">{{.Meta}}</pre></div>
</div>
</div>
{{end}}
</main>
`))

func agoShort(t *time.Time) string {
	if t == nil {
		return "never"
	}
	d := time.Since(*t).Round(time.Minute)
	if d < time.Minute {
		return "just now"
	}
	return d.String() + " ago"
}
