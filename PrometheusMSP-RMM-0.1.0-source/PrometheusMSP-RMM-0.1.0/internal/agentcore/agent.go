package agentcore

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/PrometheusMSP/PrometheusMSP-RMM/internal/protocol"
)

type Agent struct { cfg Config; id *Identity; api *APIClient; spool *Spool; collector *Collector; platform *Platform; verifier *JobVerifier; policy *Policy; log *slog.Logger }

func NewAgent(ctx context.Context,cfg Config,log *slog.Logger)(*Agent,error){
	if log==nil{log=slog.Default()};idPath:=filepath.Join(cfg.StateDir,"identity.json");id,e:=LoadIdentity(idPath)
	if errors.Is(e,os.ErrNotExist){if cfg.EnrollmentToken==""{return nil,errors.New("enrollment token is required for first start")};pub,priv,e:=GenerateDeviceKey();if e!=nil{return nil,e};bootstrap,e:=NewBootstrapClient(cfg);if e!=nil{return nil,e};resp,e:=bootstrap.Enroll(ctx,cfg,pub);if e!=nil{return nil,fmt.Errorf("enroll: %w",e)};id=&Identity{DeviceID:resp.DeviceID,TenantID:resp.TenantID,PrivateKeyPEM:priv,CertificatePEM:resp.CertificatePEM,CACertificatePEM:resp.CACertificatePEM,ServerSigningKey:resp.ServerSigningKey};if e=SaveIdentity(idPath,id);e!=nil{return nil,e}
	}else if e!=nil{return nil,e}
	api,e:=NewAuthenticatedClient(cfg,id);if e!=nil{return nil,e};spool,e:=NewSpool(filepath.Join(cfg.StateDir,"spool"),cfg.SpoolMaxBytes);if e!=nil{return nil,e};replay,e:=LoadReplayStore(filepath.Join(cfg.StateDir,"replay.json"));if e!=nil{return nil,e};verifier,e:=NewJobVerifier(id.ServerSigningKey,id.TenantID,id.DeviceID,replay);if e!=nil{return nil,e};platform:=NewPlatform(cfg.StateDir);return &Agent{cfg:cfg,id:id,api:api,spool:spool,collector:NewCollector(platform),platform:platform,verifier:verifier,policy:NewPolicy(cfg),log:log},nil
}

func(a *Agent)Run(ctx context.Context)error{
	defer a.api.CloseIdleConnections();poll:=time.NewTicker(a.cfg.PollInterval);defer poll.Stop();inv:=time.NewTicker(a.cfg.InventoryEvery);defer inv.Stop();events:=time.NewTicker(a.cfg.EventEvery);defer events.Stop()
	a.flush(ctx);a.heartbeat(ctx);a.inventory(ctx);a.events(ctx);a.jobs(ctx)
	for{select{case<-ctx.Done():return ctx.Err();case<-poll.C:a.flush(ctx);a.heartbeat(ctx);a.jobs(ctx);case<-inv.C:a.inventory(ctx);case<-events.C:a.events(ctx)}}
}
func(a *Agent)heartbeat(ctx context.Context){v:=protocol.Heartbeat{SchemaVersion:protocol.SchemaVersion,DeviceID:a.id.DeviceID,AgentVersion:AgentVersion,ObservedAt:time.Now().UTC(),UptimeSeconds:a.collector.Uptime(),QueueDepth:a.spool.Depth()};a.sendOrSpool(ctx,"heartbeat",v,func()error{return a.api.Heartbeat(ctx,v)})}
func(a *Agent)inventory(ctx context.Context){v,e:=a.collector.Inventory(ctx,a.id.DeviceID);if e!=nil{a.log.Warn("inventory collection failed","error",e);return};a.sendOrSpool(ctx,"inventory",v,func()error{return a.api.UploadInventory(ctx,v)})}
func(a *Agent)events(ctx context.Context){v,e:=a.collector.Events(ctx,a.id.DeviceID);if e!=nil{a.log.Warn("event collection failed","error",e);return};if len(v.Events)==0{return};a.sendOrSpool(ctx,"events",v,func()error{return a.api.UploadEvents(ctx,v)})}
func(a *Agent)jobs(ctx context.Context){jobs,e:=a.api.PollJobs(ctx);if e!=nil{a.log.Warn("job poll failed","error",e);return};for _,j:=range jobs{a.runJob(ctx,j)}}
func(a *Agent)runJob(ctx context.Context,j protocol.JobEnvelope){start:=time.Now().UTC();result:=protocol.JobResult{JobID:j.ID,DeviceID:a.id.DeviceID,StartedAt:start,Status:"rejected",ExitCode:1};if e:=a.verifier.Verify(j);e!=nil{result.Error=e.Error()}else{out,e:=a.policy.Execute(ctx,a.platform,j);result.Output=bounded(out);if e!=nil{result.Status="failed";result.Error=e.Error()}else{result.Status="succeeded";result.ExitCode=0};if b,e:=CanonicalJobBytes(j);e==nil{sum:=sha256.Sum256(b);result.Integrity=map[string]string{"envelope_sha256":hex.EncodeToString(sum[:]),"signature_algorithm":"Ed25519"}}};result.CompletedAt=time.Now().UTC();a.sendOrSpool(ctx,"result",result,func()error{return a.api.SubmitResult(ctx,result)})}
func(a *Agent)sendOrSpool(ctx context.Context,kind string,v any,send func()error){if e:=send();e!=nil{if se:=a.spool.Enqueue(kind,v);se!=nil{a.log.Error("telemetry delivery and spool failed","kind",kind,"delivery_error",e,"spool_error",se)}else{a.log.Warn("delivery failed; item spooled","kind",kind,"error",e)}}}
func(a *Agent)flush(ctx context.Context){e:=a.spool.Drain(func(i SpoolItem)error{switch i.Kind{case"heartbeat":var v protocol.Heartbeat;if e:=json.Unmarshal(i.Body,&v);e!=nil{return nil};return a.api.Heartbeat(ctx,v);case"inventory":var v protocol.Inventory;if e:=json.Unmarshal(i.Body,&v);e!=nil{return nil};return a.api.UploadInventory(ctx,v);case"events":var v protocol.EventBatch;if e:=json.Unmarshal(i.Body,&v);e!=nil{return nil};return a.api.UploadEvents(ctx,v);case"result":var v protocol.JobResult;if e:=json.Unmarshal(i.Body,&v);e!=nil{return nil};return a.api.SubmitResult(ctx,v);default:return nil}});if e!=nil{a.log.Warn("spool flush stopped","error",e)}}
