package app

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"html/template"
	"os"
	"strings"
	"time"

	qrcode "github.com/skip2/go-qrcode"

	"github.com/buildsnap-dev/secretree/internal/keys"
)

// KitHTML writes a printable recovery kit: the same text as the plain kit
// plus QR codes for the age identity and the signing key, so a phone can
// read them back without typing 70 characters of Bech32.
func (a *App) KitHTML(dir, out string) error {
	r, err := a.openRepo(dir)
	if err != nil {
		return err
	}
	fp, _ := r.Keys.Fingerprint()
	ageQR, err := qrPNG(strings.TrimSpace(r.Keys.AgeIdentity))
	if err != nil {
		return err
	}
	sigQR, err := qrPNG(r.Keys.SigningKeyPEM)
	if err != nil {
		return err
	}
	plain, err := r.Keys.RecoveryKit(r.Cfg.VaultURL)
	if err != nil {
		return err
	}
	var buf bytes.Buffer
	err = kitTmpl.Execute(&buf, map[string]any{
		"Plain": plain,
		"Label": r.Cfg.Label, "VaultID": r.Keys.VaultID, "VaultURL": r.Cfg.VaultURL, "Fingerprint": fp,
		"Printed": time.Now().UTC().Format("2006-01-02 15:04 UTC"),
		"Age":     strings.TrimSpace(r.Keys.AgeIdentity), "Sig": strings.TrimSpace(r.Keys.SigningKeyPEM),
		"AgeQR": ageQR, "SigQR": sigQR,
	})
	if err != nil {
		return err
	}
	if out == "" {
		out = "secretree-recovery-kit-" + r.Keys.VaultID + ".html"
	}
	if err := os.WriteFile(out, buf.Bytes(), 0o600); err != nil {
		return err
	}
	a.logf("printable recovery kit written to %s", out)
	a.logf("print it (File → Print, or: secretree kit --print %s), confirm with: secretree kit --confirm, then delete the file", out)
	_ = keys.Namespace
	return nil
}

func qrPNG(text string) (template.URL, error) {
	png, err := qrcode.Encode(text, qrcode.Medium, 220)
	if err != nil {
		return "", fmt.Errorf("qr: %w", err)
	}
	return template.URL("data:image/png;base64," + base64.StdEncoding.EncodeToString(png)), nil
}

var kitTmpl = template.Must(template.New("kit").Parse(`<!doctype html>
<meta charset="utf-8"><title>secretree recovery kit · {{.Label}}</title>
<style>
body{font:13px/1.5 -apple-system,system-ui,sans-serif;color:#000;background:#fff;max-width:720px;margin:24px auto;padding:0 16px}
h1{font-size:22px;margin:0 0 4px}h2{font-size:14px;margin:22px 0 6px;border-top:1px solid #000;padding-top:8px}
.warn{border:2px solid #000;padding:8px 12px;margin:12px 0;font-weight:600}
table{border-collapse:collapse}td{padding:2px 12px 2px 0;vertical-align:top}
pre{font:11px/1.4 ui-monospace,Menlo,monospace;white-space:pre-wrap;word-break:break-all;margin:6px 0}
.row{display:flex;gap:18px;align-items:flex-start}.row img{width:170px;height:170px;flex:none;image-rendering:pixelated}
@media print{body{margin:0}.noprint{display:none}}
</style>
<h1>secretree recovery kit</h1>
<div>{{.Label}} · printed {{.Printed}}</div>
<div class="warn">Anyone holding this page can read every backup of this vault. Keep it on paper, in a safe place. Do not photograph it into a cloud library.</div>
<table>
<tr><td>Vault ID</td><td><code>{{.VaultID}}</code></td></tr>
<tr><td>Vault URL</td><td><code>{{.VaultURL}}</code></td></tr>
<tr><td>Signing key fingerprint</td><td><code>{{.Fingerprint}}</code> — check this against <code>vault.json</code> before trusting anything else</td></tr>
</table>
<h2>How to restore</h2>
<p>Install secretree (https://secretree.dev/docs/install), then: <code>secretree restore --vault {{.VaultURL}} --to ./restored --from-recovery-kit kit.txt</code>, where <code>kit.txt</code> is this page saved as text, or the two keys below typed or scanned into a file. Without secretree: <code>git</code>, <code>age</code> and <code>ssh-keygen</code> suffice; see https://secretree.dev/docs/backup#restore-by-hand and the vault's own README.</p>
<h2>age identity (decryption key)</h2>
<div class="row"><img src="{{.AgeQR}}" alt="QR: age identity"><pre>{{.Age}}</pre></div>
<h2>signing key (OpenSSH)</h2>
<div class="row"><img src="{{.SigQR}}" alt="QR: signing key"><pre>{{.Sig}}</pre></div>
<p class="noprint"><button onclick="print()">Print</button></p>
<!-- the plain-text kit, so this file itself works as --from-recovery-kit -->
<script type="text/plain" id="kit">
{{.Plain}}</script>
`))
