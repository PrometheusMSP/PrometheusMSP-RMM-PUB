package store

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/PrometheusMSP/PrometheusMSP-RMM/internal/protocol"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Postgres struct{ pool *pgxpool.Pool }

func OpenPostgres(ctx context.Context, dsn string) (*Postgres, error) {
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil { return nil, fmt.Errorf("parse database URL: %w", err) }
	config.MaxConns = 20
	config.MinConns = 2
	config.MaxConnLifetime = time.Hour
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil { return nil, fmt.Errorf("open database: %w", err) }
	return &Postgres{pool: pool}, nil
}

func (p *Postgres) Close() { p.pool.Close() }
func (p *Postgres) Ready(ctx context.Context) error { return p.pool.Ping(ctx) }

func (p *Postgres) CreateEnrollmentToken(ctx context.Context, tenantID string, tokenHash []byte, expiresAt time.Time) error {
	command, err := p.pool.Exec(ctx, `INSERT INTO enrollment_tokens(token_hash,tenant_id,expires_at)
		SELECT $1,id,$3 FROM tenants WHERE id=$2`, tokenHash, tenantID, expiresAt)
	if err == nil && command.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

func (p *Postgres) Enroll(ctx context.Context, tokenHash []byte, device Device) (Device, error) {
	tx, err := p.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil { return Device{}, err }
	defer tx.Rollback(ctx)
	var tenantID string
	err = tx.QueryRow(ctx, `
		UPDATE enrollment_tokens SET used_at=now()
		WHERE token_hash=$1 AND used_at IS NULL AND expires_at > now()
		RETURNING tenant_id`, tokenHash).Scan(&tenantID)
	if errors.Is(err, pgx.ErrNoRows) { return Device{}, ErrInvalidToken }
	if err != nil { return Device{}, err }
	device.TenantID = tenantID
	labels, err := json.Marshal(device.Labels)
	if err != nil { return Device{}, err }
	_, err = tx.Exec(ctx, `INSERT INTO devices
		(id,tenant_id,name,platform,agent_version,labels,created_at)
		VALUES($1,$2,$3,$4,$5,$6,$7)`, device.ID, tenantID, device.Name, device.Platform, device.AgentVersion, labels, device.CreatedAt)
	if err != nil { return Device{}, err }
	if err := tx.Commit(ctx); err != nil { return Device{}, err }
	return device, nil
}

func (p *Postgres) DeviceExists(ctx context.Context, tenantID, deviceID string) error {
	var one int
	err := p.pool.QueryRow(ctx, `SELECT 1 FROM devices WHERE tenant_id=$1 AND id=$2`, tenantID, deviceID).Scan(&one)
	if errors.Is(err, pgx.ErrNoRows) { return ErrNotFound }
	return err
}

func (p *Postgres) SaveHeartbeat(ctx context.Context, tenantID, deviceID string, heartbeat protocol.Heartbeat) error {
	payload, err := json.Marshal(heartbeat); if err != nil { return err }
	command, err := p.pool.Exec(ctx, `WITH target AS (
		UPDATE devices SET last_seen_at=$3,agent_version=$4 WHERE tenant_id=$1 AND id=$2 RETURNING id)
		INSERT INTO heartbeats(tenant_id,device_id,observed_at,payload)
		SELECT $1,id,$3,$5 FROM target`, tenantID, deviceID, heartbeat.ObservedAt, heartbeat.AgentVersion, payload)
	if err == nil && command.RowsAffected() == 0 { return ErrNotFound }
	return err
}

func (p *Postgres) SaveInventory(ctx context.Context, tenantID, deviceID string, inventory protocol.Inventory) error {
	payload, err := json.Marshal(inventory); if err != nil { return err }
	command, err := p.pool.Exec(ctx, `INSERT INTO inventories(tenant_id,device_id,collected_at,payload)
		SELECT $1,id,$3,$4 FROM devices WHERE tenant_id=$1 AND id=$2
		ON CONFLICT(tenant_id,device_id) DO UPDATE SET collected_at=excluded.collected_at,payload=excluded.payload`,
		tenantID, deviceID, inventory.CollectedAt, payload)
	if err == nil && command.RowsAffected() == 0 { return ErrNotFound }
	return err
}

func (p *Postgres) SaveEvents(ctx context.Context, tenantID, deviceID string, batch protocol.EventBatch) error {
	tx, err := p.pool.Begin(ctx); if err != nil { return err }; defer tx.Rollback(ctx)
	var exists bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM devices WHERE tenant_id=$1 AND id=$2)`, tenantID, deviceID).Scan(&exists); err != nil { return err }
	if !exists { return ErrNotFound }
	for _, event := range batch.Events {
		payload, err := marshalEventForJSONB(event); if err != nil { return err }
		_, err = tx.Exec(ctx, `INSERT INTO events(id,tenant_id,device_id,occurred_at,source,severity,payload)
			VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(tenant_id,device_id,id) DO NOTHING`,
			event.ID, tenantID, deviceID, event.OccurredAt, event.Source, event.Severity, payload)
		if err != nil { return err }
	}
	_, err = tx.Exec(ctx, `INSERT INTO event_checkpoints(tenant_id,device_id,checkpoint,updated_at)
		VALUES($1,$2,$3,now()) ON CONFLICT(tenant_id,device_id) DO UPDATE SET checkpoint=excluded.checkpoint,updated_at=now()`, tenantID, deviceID, batch.Checkpoint)
	if err != nil { return err }
	return tx.Commit(ctx)
}

func (p *Postgres) ListDevices(ctx context.Context, tenantID string, limit int, after string) ([]Device, error) {
	rows, err := p.pool.Query(ctx, `SELECT id,tenant_id,name,platform,agent_version,labels,created_at,last_seen_at
		FROM devices WHERE tenant_id=$1 AND (NULLIF($2::text, '') IS NULL OR id > NULLIF($2::text, '')::uuid) ORDER BY id LIMIT $3`, tenantID, after, limit)
	if err != nil { return nil, err }; defer rows.Close()
	var out []Device
	for rows.Next() {
		var d Device; var labels []byte
		if err := rows.Scan(&d.ID,&d.TenantID,&d.Name,&d.Platform,&d.AgentVersion,&labels,&d.CreatedAt,&d.LastSeenAt); err != nil { return nil, err }
		if err := json.Unmarshal(labels,&d.Labels); err != nil { return nil, err }; out=append(out,d)
	}
	return out, rows.Err()
}

func (p *Postgres) GetDevice(ctx context.Context, tenantID, deviceID string) (Device, error) {
	var d Device
	var labels []byte
	err := p.pool.QueryRow(ctx, `SELECT id,tenant_id,name,platform,agent_version,labels,created_at,last_seen_at FROM devices WHERE tenant_id=$1 AND id=$2`, tenantID, deviceID).Scan(&d.ID,&d.TenantID,&d.Name,&d.Platform,&d.AgentVersion,&labels,&d.CreatedAt,&d.LastSeenAt)
	if errors.Is(err,pgx.ErrNoRows){return Device{},ErrNotFound};if err!=nil{return Device{},err};if err:=json.Unmarshal(labels,&d.Labels);err!=nil{return Device{},err};return d,nil
}

func (p *Postgres) GetInventory(ctx context.Context, tenantID, deviceID string) (protocol.Inventory, error) {
	var payload []byte
	err:=p.pool.QueryRow(ctx,`SELECT payload FROM inventories WHERE tenant_id=$1 AND device_id=$2`,tenantID,deviceID).Scan(&payload)
	if errors.Is(err,pgx.ErrNoRows){return protocol.Inventory{},ErrNotFound};if err!=nil{return protocol.Inventory{},err};var inventory protocol.Inventory;if err:=json.Unmarshal(payload,&inventory);err!=nil{return protocol.Inventory{},err};return inventory,nil
}

func (p *Postgres) ListEvents(ctx context.Context,tenantID,deviceID,severity string,before time.Time,limit int)([]protocol.Event,error){
	if before.IsZero(){before=time.Now().Add(100*365*24*time.Hour)}
	rows,err:=p.pool.Query(ctx,`SELECT payload FROM events WHERE tenant_id=$1 AND device_id=$2 AND occurred_at<$3 AND ($4='' OR severity=$4) ORDER BY occurred_at DESC LIMIT $5`,tenantID,deviceID,before,severity,limit);if err!=nil{return nil,err};defer rows.Close();var events []protocol.Event
	for rows.Next(){var payload []byte;if err:=rows.Scan(&payload);err!=nil{return nil,err};var event protocol.Event;if err:=json.Unmarshal(payload,&event);err!=nil{return nil,err};events=append(events,event)};return events,rows.Err()
}

func (p *Postgres) CreateJob(ctx context.Context, input NewJob) (Job, error) {
	command, err := p.pool.Exec(ctx, `INSERT INTO jobs
		(id,tenant_id,device_id,issued_at,expires_at,nonce,action,parameters,risk,requested_by,approved_by,signature,status)
		SELECT $1,$2,id,$4,$5,$6,$7,$8,$9,$10,NULLIF($11,''),NULLIF($12,''),$13 FROM devices WHERE tenant_id=$2 AND id=$3`,
		input.ID,input.TenantID,input.DeviceID,input.IssuedAt,input.ExpiresAt,input.Nonce,input.Action,input.Parameters,input.Risk,input.RequestedBy,input.ApprovedBy,input.Signature,input.Status)
	if err == nil && command.RowsAffected()==0 { return Job{}, ErrNotFound }
	if err != nil { return Job{}, err }
	return jobFromNew(input), nil
}

func (p *Postgres) ListJobs(ctx context.Context, tenantID, deviceID, status string, limit int) ([]Job, error) {
	rows, err := p.pool.Query(ctx, `SELECT id,tenant_id,device_id,issued_at,expires_at,nonce,action,parameters,risk,
		COALESCE(approved_by,''),COALESCE(signature,''),status,requested_by
		FROM jobs WHERE tenant_id=$1 AND ($2='' OR device_id::text=$2) AND ($3='' OR status=$3)
		ORDER BY issued_at DESC LIMIT $4`, tenantID, deviceID, status, limit)
	if err != nil { return nil, err }
	defer rows.Close()
	var jobs []Job
	for rows.Next() {
		job, err := scanJob(rows)
		if err != nil { return nil, err }
		jobs = append(jobs, job)
	}
	return jobs, rows.Err()
}

func (p *Postgres) GetJob(ctx context.Context, tenantID, jobID string) (Job, error) {
	return scanJob(p.pool.QueryRow(ctx, `SELECT id,tenant_id,device_id,issued_at,expires_at,nonce,action,parameters,risk,COALESCE(approved_by,''),COALESCE(signature,''),status,requested_by FROM jobs WHERE tenant_id=$1 AND id=$2`, tenantID, jobID))
}

func (p *Postgres) ApproveJob(ctx context.Context, tenantID, jobID, approver, signature string) (Job, error) {
	row := p.pool.QueryRow(ctx, `UPDATE jobs SET approved_by=$3,signature=$4,status='approved'
		WHERE tenant_id=$1 AND id=$2 AND status='pending' AND expires_at>now()
		RETURNING id,tenant_id,device_id,issued_at,expires_at,nonce,action,parameters,risk,approved_by,signature,status,requested_by`, tenantID,jobID,approver,signature)
	return scanJob(row)
}

func (p *Postgres) DispatchableJobs(ctx context.Context, tenantID, deviceID string, now time.Time, limit int) ([]protocol.JobEnvelope,error) {
	rows,err:=p.pool.Query(ctx,`UPDATE jobs SET status='dispatched',dispatched_at=$3
		WHERE id IN (SELECT id FROM jobs WHERE tenant_id=$1 AND device_id=$2 AND status='approved' AND expires_at>$3 ORDER BY issued_at LIMIT $4 FOR UPDATE SKIP LOCKED)
		RETURNING id,tenant_id,device_id,issued_at,expires_at,nonce,action,parameters,risk,COALESCE(approved_by,''),signature`,tenantID,deviceID,now,limit)
	if err!=nil{return nil,err}; defer rows.Close(); var jobs []protocol.JobEnvelope
	for rows.Next(){var e protocol.JobEnvelope;if err:=rows.Scan(&e.ID,&e.TenantID,&e.DeviceID,&e.IssuedAt,&e.ExpiresAt,&e.Nonce,&e.Action,&e.Parameters,&e.Risk,&e.ApprovedBy,&e.Signature);err!=nil{return nil,err};jobs=append(jobs,e)}
	return jobs,rows.Err()
}

func (p *Postgres) SaveJobResult(ctx context.Context, tenantID, deviceID string, result protocol.JobResult) error {
	payload,err:=json.Marshal(result);if err!=nil{return err}
	command,err:=p.pool.Exec(ctx,`UPDATE jobs SET status='completed',completed_at=$4,result=$5
		WHERE tenant_id=$1 AND device_id=$2 AND id=$3 AND status IN ('approved','dispatched')`,tenantID,deviceID,result.JobID,result.CompletedAt,payload)
	if err==nil&&command.RowsAffected()==0{return ErrNotFound};return err
}

func (p *Postgres) AppendAudit(ctx context.Context, event AuditEvent) error {
	_,err:=p.pool.Exec(ctx,`INSERT INTO audit_events(id,tenant_id,actor,action,target_type,target_id,occurred_at,correlation_id,details)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`,event.ID,event.TenantID,event.Actor,event.Action,event.TargetType,event.TargetID,event.OccurredAt,event.CorrelationID,event.Details);return err
}

func (p *Postgres) ListAudit(ctx context.Context,tenantID string,limit int)([]AuditEvent,error){
	rows,err:=p.pool.Query(ctx,`SELECT id,tenant_id,actor,action,target_type,target_id,occurred_at,correlation_id,details FROM audit_events WHERE tenant_id=$1 ORDER BY occurred_at DESC LIMIT $2`,tenantID,limit);if err!=nil{return nil,err};defer rows.Close();var out []AuditEvent
	for rows.Next(){var e AuditEvent;if err:=rows.Scan(&e.ID,&e.TenantID,&e.Actor,&e.Action,&e.TargetType,&e.TargetID,&e.OccurredAt,&e.CorrelationID,&e.Details);err!=nil{return nil,err};out=append(out,e)};return out,rows.Err()
}

type scanner interface{Scan(...any)error}
func scanJob(row scanner)(Job,error){var j Job;err:=row.Scan(&j.Envelope.ID,&j.Envelope.TenantID,&j.Envelope.DeviceID,&j.Envelope.IssuedAt,&j.Envelope.ExpiresAt,&j.Envelope.Nonce,&j.Envelope.Action,&j.Envelope.Parameters,&j.Envelope.Risk,&j.Envelope.ApprovedBy,&j.Envelope.Signature,&j.Status,&j.RequestedBy);if errors.Is(err,pgx.ErrNoRows){return Job{},ErrNotFound};return j,err}
func jobFromNew(n NewJob)Job{return Job{Envelope:protocol.JobEnvelope{ID:n.ID,TenantID:n.TenantID,DeviceID:n.DeviceID,IssuedAt:n.IssuedAt,ExpiresAt:n.ExpiresAt,Nonce:n.Nonce,Action:n.Action,Parameters:n.Parameters,Risk:n.Risk,ApprovedBy:n.ApprovedBy,Signature:n.Signature},Status:n.Status,RequestedBy:n.RequestedBy}}

func HashEnrollmentToken(token string)[]byte{sum:=sha256.Sum256([]byte(token));return sum[:]}
