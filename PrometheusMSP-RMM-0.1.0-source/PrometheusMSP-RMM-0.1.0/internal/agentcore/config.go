package agentcore

import (
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const AgentVersion = "0.1.0"

type Config struct {
	ServerURL        string
	BootstrapCAFile  string
	EnrollmentToken  string
	StateDir         string
	Hostname         string
	PollInterval     time.Duration
	InventoryEvery   time.Duration
	EventEvery       time.Duration
	RequestTimeout   time.Duration
	SpoolMaxBytes    int64
	DryRun           bool
	AllowedServices  []string
	AllowedPackages  []string
	AllowTempCleanup bool
	AllowReboot      bool
	AllowSoftware    bool
	AllowPatching    bool
	ActionTimeout    time.Duration
}

func ConfigFromEnv() (Config, error) {
	host, _ := os.Hostname()
	c := Config{
		ServerURL:        strings.TrimRight(os.Getenv("PROMETHEUS_SERVER_URL"), "/"),
		BootstrapCAFile:  os.Getenv("PROMETHEUS_BOOTSTRAP_CA_FILE"),
		EnrollmentToken:  os.Getenv("PROMETHEUS_ENROLLMENT_TOKEN"),
		StateDir:         envOr("PROMETHEUS_STATE_DIR", defaultStateDir()),
		Hostname:         envOr("PROMETHEUS_DEVICE_NAME", host),
		PollInterval:     durationOr("PROMETHEUS_POLL_INTERVAL", 30*time.Second),
		InventoryEvery:   durationOr("PROMETHEUS_INVENTORY_INTERVAL", 30*time.Minute),
		EventEvery:       durationOr("PROMETHEUS_EVENT_INTERVAL", time.Minute),
		RequestTimeout:   durationOr("PROMETHEUS_REQUEST_TIMEOUT", 30*time.Second),
		SpoolMaxBytes:    int64Or("PROMETHEUS_SPOOL_MAX_BYTES", 64<<20),
		DryRun:           boolOr("PROMETHEUS_DRY_RUN", true),
		AllowedServices:  splitCSV(os.Getenv("PROMETHEUS_ALLOWED_SERVICES")),
		AllowedPackages:  splitCSV(os.Getenv("PROMETHEUS_ALLOWED_PACKAGES")),
		AllowTempCleanup: boolOr("PROMETHEUS_ALLOW_TEMP_CLEANUP", false),
		AllowReboot:      boolOr("PROMETHEUS_ALLOW_REBOOT", false),
		AllowSoftware:    boolOr("PROMETHEUS_ALLOW_SOFTWARE", false),
		AllowPatching:    boolOr("PROMETHEUS_ALLOW_PATCHING", false),
		ActionTimeout:    durationOr("PROMETHEUS_ACTION_TIMEOUT", 30*time.Minute),
	}
	if c.ServerURL == "" {
		return Config{}, errors.New("PROMETHEUS_SERVER_URL is required")
	}
	u, err := url.Parse(c.ServerURL)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return Config{}, errors.New("PROMETHEUS_SERVER_URL must be an absolute https URL")
	}
	if c.SpoolMaxBytes < 1024 || c.PollInterval < time.Second {
		return Config{}, errors.New("invalid spool size or poll interval")
	}
	return c, nil
}

func defaultStateDir() string {
	if os.PathSeparator == '\\' {
		if d := os.Getenv("ProgramData"); d != "" {
			return filepath.Join(d, "PrometheusMSP", "Agent")
		}
	}
	return "/var/lib/prometheus-rmm-agent"
}

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}
func durationOr(k string, d time.Duration) time.Duration {
	if v, e := time.ParseDuration(os.Getenv(k)); e == nil {
		return v
	}
	return d
}
func int64Or(k string, d int64) int64 {
	if v, e := strconv.ParseInt(os.Getenv(k), 10, 64); e == nil {
		return v
	}
	return d
}
func boolOr(k string, d bool) bool {
	if v := os.Getenv(k); v != "" {
		if b, e := strconv.ParseBool(v); e == nil {
			return b
		}
	}
	return d
}
func splitCSV(v string) []string {
	var out []string
	for _, p := range strings.Split(v, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
