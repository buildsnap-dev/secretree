package app

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/buildsnap-dev/secretree/internal/config"
)

// UIInstall keeps `secretree ui` running in the background (launchd on
// macOS, a systemd user service on Linux) so permalinks always resolve.
func (a *App) UIInstall(dir, listen string, remove bool) error {
	work, gitDir, err := locateRepo(dir)
	if err != nil {
		return err
	}
	cfg, err := config.Load(config.NewPaths(gitDir))
	if err != nil {
		return err
	}
	if listen == "" {
		listen = DefaultUIAddr
	}
	exe := exePath()
	id := "secretree-ui-" + cfg.RepoID
	home, _ := os.UserHomeDir()
	switch runtime.GOOS {
	case "darwin":
		label := "dev." + id
		plist := filepath.Join(home, "Library", "LaunchAgents", label+".plist")
		domain := fmt.Sprintf("gui/%d", os.Getuid())
		if remove {
			_ = exec.Command("launchctl", "bootout", domain+"/"+label).Run()
			_ = os.Remove(plist)
			a.logf("ui service removed (%s)", label)
			return nil
		}
		logDir := filepath.Join(home, "Library", "Logs", "secretree")
		_ = os.MkdirAll(logDir, 0o755)
		_ = os.MkdirAll(filepath.Dir(plist), 0o755)
		content := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
	<key>Label</key><string>%s</string>
	<key>ProgramArguments</key><array><string>%s</string><string>-C</string><string>%s</string><string>ui</string><string>--listen</string><string>%s</string></array>
	<key>RunAtLoad</key><true/>
	<key>KeepAlive</key><true/>
	<key>StandardOutPath</key><string>%s</string>
	<key>StandardErrorPath</key><string>%s</string>
	<key>EnvironmentVariables</key><dict><key>PATH</key><string>/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin</string></dict>
</dict></plist>
`, label, exe, work, listen, filepath.Join(logDir, id+".log"), filepath.Join(logDir, id+".log"))
		if err := os.WriteFile(plist, []byte(content), 0o644); err != nil {
			return err
		}
		_ = exec.Command("launchctl", "bootout", domain+"/"+label).Run()
		if out, err := exec.Command("launchctl", "bootstrap", domain, plist).CombinedOutput(); err != nil {
			return fmt.Errorf("launchctl bootstrap: %s", strings.TrimSpace(string(out)))
		}
		a.logf("ui service installed: http://%s (runs while you are logged in; log %s)", listen, filepath.Join(logDir, id+".log"))
		return nil
	case "linux":
		dir := filepath.Join(home, ".config", "systemd", "user")
		unit := filepath.Join(dir, id+".service")
		if remove {
			_ = exec.Command("systemctl", "--user", "disable", "--now", id+".service").Run()
			_ = os.Remove(unit)
			_ = exec.Command("systemctl", "--user", "daemon-reload").Run()
			a.logf("ui service removed (%s)", id)
			return nil
		}
		_ = os.MkdirAll(dir, 0o755)
		content := fmt.Sprintf("[Unit]\nDescription=secretree ui for %s\n\n[Service]\nExecStart=%s -C %s ui --listen %s\nRestart=always\n\n[Install]\nWantedBy=default.target\n", work, exe, work, listen)
		if err := os.WriteFile(unit, []byte(content), 0o644); err != nil {
			return err
		}
		if out, err := exec.Command("systemctl", "--user", "daemon-reload").CombinedOutput(); err != nil {
			return fmt.Errorf("daemon-reload: %s", strings.TrimSpace(string(out)))
		}
		if out, err := exec.Command("systemctl", "--user", "enable", "--now", id+".service").CombinedOutput(); err != nil {
			return fmt.Errorf("enable: %s", strings.TrimSpace(string(out)))
		}
		a.logf("ui service installed: http://%s (journalctl --user -u %s)", listen, id)
		return nil
	default:
		return errors.New("background UI service is supported on macOS and Linux")
	}
}
