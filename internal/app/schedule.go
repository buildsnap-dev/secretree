package app

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/buildsnap-dev/secretree/internal/config"
)

// ScheduleOptions configures Schedule.
type ScheduleOptions struct {
	Dir    string
	Every  time.Duration // interval; 0 with Daily set = calendar schedule
	Daily  string        // "HH:MM"
	Remove bool
	Show   bool
}

// Schedule installs (or removes) a launchd agent on macOS or a systemd user
// timer on Linux that runs `secretree backup` for this repository.
func (a *App) Schedule(o ScheduleOptions) error {
	work, gitDir, err := locateRepo(o.Dir)
	if err != nil {
		return err
	}
	cfg, err := config.Load(config.NewPaths(gitDir))
	if err != nil {
		return err
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if exe, err = filepath.EvalSymlinks(exe); err != nil {
		return err
	}
	id := "secretree-" + cfg.RepoID
	switch runtime.GOOS {
	case "darwin":
		return a.scheduleLaunchd(id, exe, work, o)
	case "linux":
		return a.scheduleSystemd(id, exe, work, o)
	default:
		return fmt.Errorf("scheduling is not supported on %s; run `secretree backup` from your own scheduler", runtime.GOOS)
	}
}

func parseDaily(s string) (int, int, error) {
	p := strings.Split(s, ":")
	if len(p) != 2 {
		return 0, 0, errors.New("--daily wants HH:MM")
	}
	h, err1 := strconv.Atoi(p[0])
	m, err2 := strconv.Atoi(p[1])
	if err1 != nil || err2 != nil || h < 0 || h > 23 || m < 0 || m > 59 {
		return 0, 0, errors.New("--daily wants HH:MM")
	}
	return h, m, nil
}

func (a *App) scheduleLaunchd(id, exe, work string, o ScheduleOptions) error {
	home, _ := os.UserHomeDir()
	label := "dev." + id
	plist := filepath.Join(home, "Library", "LaunchAgents", label+".plist")
	logDir := filepath.Join(home, "Library", "Logs", "secretree")
	uid := os.Getuid()
	domain := fmt.Sprintf("gui/%d", uid)
	if o.Show {
		data, err := os.ReadFile(plist)
		if errors.Is(err, os.ErrNotExist) {
			a.logf("no schedule installed (%s)", plist)
			return nil
		}
		fmt.Fprint(a.Out, string(data))
		return nil
	}
	if o.Remove {
		_ = exec.Command("launchctl", "bootout", domain+"/"+label).Run()
		if err := os.Remove(plist); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		a.logf("schedule removed (%s)", label)
		return nil
	}
	var trigger string
	switch {
	case o.Daily != "":
		h, m, err := parseDaily(o.Daily)
		if err != nil {
			return err
		}
		trigger = fmt.Sprintf("\t<key>StartCalendarInterval</key>\n\t<dict><key>Hour</key><integer>%d</integer><key>Minute</key><integer>%d</integer></dict>\n", h, m)
	case o.Every > 0:
		trigger = fmt.Sprintf("\t<key>StartInterval</key>\n\t<integer>%d</integer>\n", int(o.Every.Seconds()))
	default:
		return errors.New("pass --every <duration> or --daily HH:MM")
	}
	if err := os.MkdirAll(filepath.Dir(plist), 0o755); err != nil {
		return err
	}
	if err := os.MkdirAll(logDir, 0o755); err != nil {
		return err
	}
	content := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>%s</string>
	<key>ProgramArguments</key>
	<array>
		<string>%s</string>
		<string>-C</string>
		<string>%s</string>
		<string>backup</string>
	</array>
%s	<key>RunAtLoad</key>
	<false/>
	<key>StandardOutPath</key>
	<string>%s</string>
	<key>StandardErrorPath</key>
	<string>%s</string>
	<key>EnvironmentVariables</key>
	<dict>
		<key>PATH</key>
		<string>/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin</string>
	</dict>
</dict>
</plist>
`, label, exe, work, trigger, filepath.Join(logDir, id+".log"), filepath.Join(logDir, id+".log"))
	if err := os.WriteFile(plist, []byte(content), 0o644); err != nil {
		return err
	}
	_ = exec.Command("launchctl", "bootout", domain+"/"+label).Run()
	if out, err := exec.Command("launchctl", "bootstrap", domain, plist).CombinedOutput(); err != nil {
		return fmt.Errorf("launchctl bootstrap: %s", strings.TrimSpace(string(out)))
	}
	a.logf("schedule installed: %s\n  runs: %s -C %s backup\n  log:  %s", plist, exe, work, filepath.Join(logDir, id+".log"))
	a.logf("note: the agent uses the login Keychain; it runs only while you are logged in")
	return nil
}

func (a *App) scheduleSystemd(id, exe, work string, o ScheduleOptions) error {
	home, _ := os.UserHomeDir()
	dir := filepath.Join(home, ".config", "systemd", "user")
	service := filepath.Join(dir, id+".service")
	timer := filepath.Join(dir, id+".timer")
	if o.Show {
		data, err := os.ReadFile(timer)
		if errors.Is(err, os.ErrNotExist) {
			a.logf("no schedule installed (%s)", timer)
			return nil
		}
		fmt.Fprint(a.Out, string(data))
		return nil
	}
	if o.Remove {
		_ = exec.Command("systemctl", "--user", "disable", "--now", id+".timer").Run()
		_ = os.Remove(timer)
		_ = os.Remove(service)
		_ = exec.Command("systemctl", "--user", "daemon-reload").Run()
		a.logf("schedule removed (%s)", id)
		return nil
	}
	var onCal string
	switch {
	case o.Daily != "":
		h, m, err := parseDaily(o.Daily)
		if err != nil {
			return err
		}
		onCal = fmt.Sprintf("OnCalendar=*-*-* %02d:%02d:00\n", h, m)
	case o.Every > 0:
		onCal = fmt.Sprintf("OnBootSec=5min\nOnUnitActiveSec=%ds\n", int(o.Every.Seconds()))
	default:
		return errors.New("pass --every <duration> or --daily HH:MM")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	svc := fmt.Sprintf("[Unit]\nDescription=secretree backup of %s\n\n[Service]\nType=oneshot\nExecStart=%s -C %s backup\n", work, exe, work)
	tm := fmt.Sprintf("[Unit]\nDescription=secretree backup timer for %s\n\n[Timer]\n%sPersistent=true\n\n[Install]\nWantedBy=timers.target\n", work, onCal)
	if err := os.WriteFile(service, []byte(svc), 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(timer, []byte(tm), 0o644); err != nil {
		return err
	}
	if out, err := exec.Command("systemctl", "--user", "daemon-reload").CombinedOutput(); err != nil {
		return fmt.Errorf("systemctl daemon-reload: %s", strings.TrimSpace(string(out)))
	}
	if out, err := exec.Command("systemctl", "--user", "enable", "--now", id+".timer").CombinedOutput(); err != nil {
		return fmt.Errorf("systemctl enable: %s", strings.TrimSpace(string(out)))
	}
	a.logf("schedule installed: %s (logs: journalctl --user -u %s)", timer, id)
	return nil
}
