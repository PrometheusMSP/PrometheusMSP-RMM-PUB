package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/PrometheusMSP/PrometheusMSP-RMM/internal/protocol"
)

var (
	ErrNotFound      = errors.New("not found")
	ErrConflict      = errors.New("conflict")
	ErrInvalidToken  = errors.New("invalid or expired enrollment token")
)

type Device struct {
	ID           string            `json:"id"`
	TenantID     string            `json:"tenant_id"`
	Name         string            `json:"name"`
	Platform     string            `json:"platform"`
	AgentVersion string            `json:"agent_version"`
	Labels       map[string]string `json:"labels,omitempty"`
	CreatedAt    time.Time         `json:"created_at"`
	LastSeenAt   *time.Time        `json:"last_seen_at,omitempty"`
}

type NewJob struct {
	ID, TenantID, DeviceID, Action, Risk, RequestedBy string
	Parameters json.RawMessage
	IssuedAt, ExpiresAt time.Time
	Nonce string
	ApprovedBy string
	Signature string
	Status string
}

type Job struct {
	Envelope protocol.JobEnvelope `json:"envelope"`
	Status string `json:"status"`
	RequestedBy string `json:"requested_by"`
}

type AuditEvent struct {
	ID, TenantID, Actor, Action, TargetType, TargetID, CorrelationID string
	OccurredAt time.Time
	Details json.RawMessage
}

type Store interface {
	Ready(context.Context) error
	CreateEnrollmentToken(context.Context, string, []byte, time.Time) error
	Enroll(context.Context, []byte, Device) (Device, error)
	DeviceExists(context.Context, string, string) error
	SaveHeartbeat(context.Context, string, string, protocol.Heartbeat) error
	SaveInventory(context.Context, string, string, protocol.Inventory) error
	SaveEvents(context.Context, string, string, protocol.EventBatch) error
	ListDevices(context.Context, string, int, string) ([]Device, error)
	GetDevice(context.Context, string, string) (Device, error)
	GetInventory(context.Context, string, string) (protocol.Inventory, error)
	ListEvents(context.Context, string, string, string, time.Time, int) ([]protocol.Event, error)
	CreateJob(context.Context, NewJob) (Job, error)
	ListJobs(context.Context, string, string, string, int) ([]Job, error)
	GetJob(context.Context, string, string) (Job, error)
	ApproveJob(context.Context, string, string, string, string) (Job, error)
	DispatchableJobs(context.Context, string, string, time.Time, int) ([]protocol.JobEnvelope, error)
	SaveJobResult(context.Context, string, string, protocol.JobResult) error
	AppendAudit(context.Context, AuditEvent) error
	ListAudit(context.Context, string, int) ([]AuditEvent, error)
	Close()
}
