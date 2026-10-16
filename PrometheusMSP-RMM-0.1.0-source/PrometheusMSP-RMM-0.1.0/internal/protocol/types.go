package protocol

import (
	"encoding/json"
	"time"
)

const SchemaVersion = "v1"

type EnrollmentRequest struct {
	Token        string            `json:"token"`
	Name         string            `json:"name"`
	Platform     string            `json:"platform"`
	PublicKey    string            `json:"public_key_pem"`
	Labels       map[string]string `json:"labels,omitempty"`
	AgentVersion string          `json:"agent_version"`
}

type EnrollmentResponse struct {
	DeviceID       string `json:"device_id"`
	TenantID       string `json:"tenant_id"`
	CertificatePEM string `json:"certificate_pem"`
	CACertificatePEM string `json:"ca_certificate_pem"`
	ServerSigningKey string `json:"server_signing_key"`
	PollSeconds    int    `json:"poll_seconds"`
}

type Heartbeat struct {
	SchemaVersion string    `json:"schema_version"`
	DeviceID      string    `json:"device_id"`
	AgentVersion  string    `json:"agent_version"`
	ObservedAt    time.Time `json:"observed_at"`
	UptimeSeconds uint64    `json:"uptime_seconds"`
	QueueDepth    int       `json:"queue_depth"`
}

type Inventory struct {
	SchemaVersion string            `json:"schema_version"`
	DeviceID      string            `json:"device_id"`
	CollectedAt   time.Time         `json:"collected_at"`
	Hostname      string            `json:"hostname"`
	OS            OSInfo            `json:"os"`
	Hardware      HardwareInfo      `json:"hardware"`
	Disks         []DiskInfo        `json:"disks"`
	Networks      []NetworkInfo     `json:"networks"`
	Services      []ServiceInfo     `json:"services,omitempty"`
	Software      []SoftwareInfo    `json:"software,omitempty"`
	Processes     []ProcessInfo     `json:"processes,omitempty"`
	Metadata      map[string]string `json:"metadata,omitempty"`
}

type OSInfo struct {
	Name         string `json:"name"`
	Version      string `json:"version"`
	Build        string `json:"build,omitempty"`
	Architecture string `json:"architecture"`
}
type HardwareInfo struct {
	CPUs        int    `json:"cpus"`
	MemoryBytes uint64 `json:"memory_bytes"`
	MachineID   string `json:"machine_id,omitempty"`
}
type DiskInfo struct {
	Path       string `json:"path"`
	TotalBytes uint64 `json:"total_bytes"`
	FreeBytes  uint64 `json:"free_bytes"`
}
type NetworkInfo struct {
	Name      string   `json:"name"`
	MAC       string   `json:"mac,omitempty"`
	Addresses []string `json:"addresses"`
}
type ServiceInfo struct {
	Name   string `json:"name"`
	Status string `json:"status"`
}
type SoftwareInfo struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Publisher string `json:"publisher,omitempty"`
}
type ProcessInfo struct {
	PID  int    `json:"pid"`
	Name string `json:"name"`
}

type Event struct {
	ID            string            `json:"id"`
	SchemaVersion string            `json:"schema_version"`
	DeviceID      string            `json:"device_id"`
	OccurredAt    time.Time         `json:"occurred_at"`
	Source        string            `json:"source"`
	Severity      string            `json:"severity"`
	Provider      string            `json:"provider,omitempty"`
	EventID       string            `json:"event_id,omitempty"`
	Message       string            `json:"message"`
	Tags          map[string]string `json:"tags,omitempty"`
}

type EventBatch struct {
	Events     []Event `json:"events"`
	Checkpoint string  `json:"checkpoint,omitempty"`
}

type JobEnvelope struct {
	ID         string          `json:"id"`
	TenantID   string          `json:"tenant_id"`
	DeviceID   string          `json:"device_id"`
	IssuedAt   time.Time       `json:"issued_at"`
	ExpiresAt  time.Time       `json:"expires_at"`
	Nonce      string          `json:"nonce"`
	Action     string          `json:"action"`
	Parameters json.RawMessage `json:"parameters"`
	Risk       string          `json:"risk"`
	ApprovedBy string          `json:"approved_by,omitempty"`
	Signature  string          `json:"signature"`
}

type JobResult struct {
	JobID       string            `json:"job_id"`
	DeviceID    string            `json:"device_id"`
	StartedAt   time.Time         `json:"started_at"`
	CompletedAt time.Time         `json:"completed_at"`
	Status      string            `json:"status"`
	ExitCode    int               `json:"exit_code"`
	Output      string            `json:"output,omitempty"`
	Error       string            `json:"error,omitempty"`
	Integrity   map[string]string `json:"integrity,omitempty"`
}

type ErrorResponse struct {
	Error         string `json:"error"`
	CorrelationID string `json:"correlation_id,omitempty"`
}
