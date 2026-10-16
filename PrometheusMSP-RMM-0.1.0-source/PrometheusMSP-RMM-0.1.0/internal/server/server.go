package server

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/PrometheusMSP/PrometheusMSP-RMM/internal/protocol"
	"github.com/PrometheusMSP/PrometheusMSP-RMM/internal/security"
	"github.com/PrometheusMSP/PrometheusMSP-RMM/internal/store"
)

const maxBodyBytes = 2 << 20

type Config struct {
	Store store.Store
	CA *security.CertificateAuthority
	Signer *security.JobSigner
	Operators *security.BearerAuthenticator
	Logger *slog.Logger
	Now func() time.Time
}

type Server struct {
	store store.Store
	ca *security.CertificateAuthority
	signer *security.JobSigner
	operators *security.BearerAuthenticator
	logger *slog.Logger
	now func() time.Time
	handler http.Handler
}

type identity struct { tenantID, actor, role, deviceID string }
type contextKey int
const identityKey contextKey = 1

func New(config Config) (*Server, error) {
	if config.Store == nil || config.CA == nil || config.Signer == nil || config.Operators == nil { return nil, errors.New("server dependencies are required") }
	if config.Logger == nil { config.Logger = slog.Default() }
	if config.Now == nil { config.Now = time.Now }
	s := &Server{store: config.Store,ca:config.CA,signer:config.Signer,operators:config.Operators,logger:config.Logger,now:config.Now}
	mux:=http.NewServeMux()
	mux.HandleFunc("GET /healthz",s.health)
	mux.HandleFunc("GET /readyz",s.ready)
	mux.HandleFunc("POST /api/v1/agent/enroll",s.enroll)
	mux.Handle("POST /api/v1/agent/heartbeat",s.deviceAuth(http.HandlerFunc(s.heartbeat)))
	mux.Handle("POST /api/v1/agent/inventory",s.deviceAuth(http.HandlerFunc(s.inventory)))
	mux.Handle("POST /api/v1/agent/events",s.deviceAuth(http.HandlerFunc(s.events)))
	mux.Handle("GET /api/v1/agent/jobs",s.deviceAuth(http.HandlerFunc(s.pollJobs)))
	mux.Handle("POST /api/v1/agent/jobs/{id}/results",s.deviceAuth(http.HandlerFunc(s.jobResult)))
	mux.Handle("GET /api/v1/devices",s.operatorAuth(http.HandlerFunc(s.devices)))
	mux.Handle("GET /api/v1/devices/{id}",s.operatorAuth(http.HandlerFunc(s.device)))
	mux.Handle("GET /api/v1/devices/{id}/inventory",s.operatorAuth(http.HandlerFunc(s.deviceInventory)))
	mux.Handle("GET /api/v1/devices/{id}/events",s.operatorAuth(http.HandlerFunc(s.deviceEvents)))
	mux.Handle("POST /api/v1/enrollment-tokens",s.operatorAuth(http.HandlerFunc(s.createEnrollmentToken)))
	mux.Handle("GET /api/v1/jobs",s.operatorAuth(http.HandlerFunc(s.jobs)))
	mux.Handle("POST /api/v1/jobs",s.operatorAuth(http.HandlerFunc(s.createJob)))
	mux.Handle("POST /api/v1/jobs/{id}/approve",s.operatorAuth(http.HandlerFunc(s.approveJob)))
	mux.Handle("GET /api/v1/audit",s.operatorAuth(http.HandlerFunc(s.audit)))
	s.handler=s.middleware(mux)
	return s,nil
}

func(s *Server)Handler()http.Handler{return s.handler}

func(s *Server)middleware(next http.Handler)http.Handler{return http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
	correlation:=strings.TrimSpace(r.Header.Get("X-Correlation-ID"));if correlation==""||len(correlation)>128{correlation,_=security.NewID()}
	w.Header().Set("X-Correlation-ID",correlation);w.Header().Set("Content-Type","application/json")
	start:=s.now();rw:=&statusWriter{ResponseWriter:w,status:http.StatusOK};next.ServeHTTP(rw,r.WithContext(context.WithValue(r.Context(),correlationKey,correlation)))
	s.logger.Info("http request","method",r.Method,"path",r.URL.Path,"status",rw.status,"duration_ms",s.now().Sub(start).Milliseconds(),"correlation_id",correlation)
})}
type correlationContextKey int
const correlationKey correlationContextKey=1
type statusWriter struct{http.ResponseWriter;status int}
func(w *statusWriter)WriteHeader(status int){w.status=status;w.ResponseWriter.WriteHeader(status)}

func(s *Server)operatorAuth(next http.Handler)http.Handler{return http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){op,err:=s.operators.Authenticate(r);if err!=nil{s.fail(w,r,http.StatusUnauthorized,"unauthorized");return};next.ServeHTTP(w,r.WithContext(context.WithValue(r.Context(),identityKey,identity{tenantID:op.TenantID,actor:op.ID,role:op.Role})))})}
func(s *Server)deviceAuth(next http.Handler)http.Handler{return http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
	if r.TLS==nil||len(r.TLS.VerifiedChains)==0||len(r.TLS.VerifiedChains[0])==0{s.fail(w,r,http.StatusUnauthorized,"verified client certificate required");return}
	tenantID,deviceID,err:=security.DeviceIdentity(r.TLS.VerifiedChains[0][0]);if err!=nil{s.fail(w,r,http.StatusUnauthorized,"invalid device certificate");return}
	if err:=s.store.DeviceExists(r.Context(),tenantID,deviceID);err!=nil{s.fail(w,r,http.StatusUnauthorized,"unknown device");return}
	next.ServeHTTP(w,r.WithContext(context.WithValue(r.Context(),identityKey,identity{tenantID:tenantID,deviceID:deviceID,actor:"device:"+deviceID,role:"device"})))
})}

func(s *Server)health(w http.ResponseWriter,r *http.Request){s.write(w,http.StatusOK,map[string]string{"status":"ok"})}
func(s *Server)ready(w http.ResponseWriter,r *http.Request){ctx,cancel:=context.WithTimeout(r.Context(),2*time.Second);defer cancel();if err:=s.store.Ready(ctx);err!=nil{s.fail(w,r,http.StatusServiceUnavailable,"database unavailable");return};s.write(w,http.StatusOK,map[string]string{"status":"ready"})}

func(s *Server)enroll(w http.ResponseWriter,r *http.Request){var input protocol.EnrollmentRequest;if !s.decode(w,r,&input){return}
	if len(input.Token)<16||len(input.Name)>255||input.Name==""||input.PublicKey==""||!oneOf(input.Platform,"windows","linux"){s.fail(w,r,http.StatusBadRequest,"invalid enrollment request");return}
	if _,err:=security.ParseDevicePublicKey(input.PublicKey);err!=nil{s.fail(w,r,http.StatusBadRequest,"invalid device public key");return}
	id,err:=security.NewID();if err!=nil{s.internal(w,r,err);return};now:=s.now().UTC()
	device,err:=s.store.Enroll(r.Context(),store.HashEnrollmentToken(input.Token),store.Device{ID:id,Name:input.Name,Platform:input.Platform,AgentVersion:input.AgentVersion,Labels:input.Labels,CreatedAt:now})
	if errors.Is(err,store.ErrInvalidToken){s.fail(w,r,http.StatusUnauthorized,"invalid or expired enrollment token");return};if err!=nil{s.internal(w,r,err);return}
	cert,err:=s.ca.IssueDeviceCertificate(input.PublicKey,device.TenantID,device.ID,now);if err!=nil{s.internal(w,r,err);return}
	s.auditEvent(r,device.TenantID,"enrollment","device.enrolled","device",device.ID,map[string]any{"platform":device.Platform})
	s.write(w,http.StatusCreated,protocol.EnrollmentResponse{DeviceID:device.ID,TenantID:device.TenantID,CertificatePEM:cert,CACertificatePEM:s.ca.CertificatePEM(),ServerSigningKey:s.signer.PublicKeyBase64(),PollSeconds:30})
}

func(s *Server)heartbeat(w http.ResponseWriter,r *http.Request){id:=getIdentity(r);var input protocol.Heartbeat;if !s.decode(w,r,&input){return};if input.DeviceID!=id.deviceID||input.SchemaVersion!=protocol.SchemaVersion||input.ObservedAt.IsZero(){s.fail(w,r,http.StatusBadRequest,"invalid heartbeat");return};if err:=s.store.SaveHeartbeat(r.Context(),id.tenantID,id.deviceID,input);err!=nil{s.storeError(w,r,err);return};w.WriteHeader(http.StatusNoContent)}
func(s *Server)inventory(w http.ResponseWriter,r *http.Request){id:=getIdentity(r);var input protocol.Inventory;if !s.decode(w,r,&input){return};if input.DeviceID!=id.deviceID||input.SchemaVersion!=protocol.SchemaVersion||input.CollectedAt.IsZero(){s.fail(w,r,http.StatusBadRequest,"invalid inventory");return};if err:=s.store.SaveInventory(r.Context(),id.tenantID,id.deviceID,input);err!=nil{s.storeError(w,r,err);return};w.WriteHeader(http.StatusNoContent)}
func(s *Server)events(w http.ResponseWriter,r *http.Request){id:=getIdentity(r);var input protocol.EventBatch;if !s.decode(w,r,&input){return};if len(input.Events)>500{s.fail(w,r,http.StatusBadRequest,"event batch exceeds 500 events");return};for _,event:=range input.Events{if event.DeviceID!=id.deviceID||event.SchemaVersion!=protocol.SchemaVersion||event.ID==""||event.OccurredAt.IsZero(){s.fail(w,r,http.StatusBadRequest,"invalid event");return}};if err:=s.store.SaveEvents(r.Context(),id.tenantID,id.deviceID,input);err!=nil{s.storeError(w,r,err);return};w.WriteHeader(http.StatusNoContent)}
func(s *Server)pollJobs(w http.ResponseWriter,r *http.Request){id:=getIdentity(r);jobs,err:=s.store.DispatchableJobs(r.Context(),id.tenantID,id.deviceID,s.now().UTC(),25);if err!=nil{s.internal(w,r,err);return};if jobs==nil{jobs=[]protocol.JobEnvelope{}};s.write(w,http.StatusOK,map[string]any{"jobs":jobs})}
func(s *Server)jobResult(w http.ResponseWriter,r *http.Request){id:=getIdentity(r);var input protocol.JobResult;if !s.decode(w,r,&input){return};if input.JobID!=r.PathValue("id")||input.DeviceID!=id.deviceID||input.StartedAt.IsZero()||input.CompletedAt.Before(input.StartedAt)||!oneOf(input.Status,"succeeded","failed","rejected")||len(input.Output)>65536||len(input.Error)>8192{s.fail(w,r,http.StatusBadRequest,"invalid job result");return};if err:=s.store.SaveJobResult(r.Context(),id.tenantID,id.deviceID,input);err!=nil{s.storeError(w,r,err);return};s.auditEvent(r,id.tenantID,id.actor,"job.completed","job",input.JobID,map[string]any{"status":input.Status,"exit_code":input.ExitCode});w.WriteHeader(http.StatusNoContent)}

func(s *Server)devices(w http.ResponseWriter,r *http.Request){id:=getIdentity(r);limit:=queryLimit(r,100,250);devices,err:=s.store.ListDevices(r.Context(),id.tenantID,limit,r.URL.Query().Get("after"));if err!=nil{s.internal(w,r,err);return};s.write(w,http.StatusOK,map[string]any{"devices":devices})}
func(s *Server)device(w http.ResponseWriter,r *http.Request){actor:=getIdentity(r);device,err:=s.store.GetDevice(r.Context(),actor.tenantID,r.PathValue("id"));if err!=nil{s.storeError(w,r,err);return};s.write(w,http.StatusOK,device)}
func(s *Server)deviceInventory(w http.ResponseWriter,r *http.Request){actor:=getIdentity(r);inventory,err:=s.store.GetInventory(r.Context(),actor.tenantID,r.PathValue("id"));if err!=nil{s.storeError(w,r,err);return};s.write(w,http.StatusOK,inventory)}
func(s *Server)deviceEvents(w http.ResponseWriter,r *http.Request){actor:=getIdentity(r);var before time.Time;if value:=r.URL.Query().Get("before");value!=""{parsed,err:=time.Parse(time.RFC3339,value);if err!=nil{s.fail(w,r,http.StatusBadRequest,"before must be RFC3339");return};before=parsed};events,err:=s.store.ListEvents(r.Context(),actor.tenantID,r.PathValue("id"),r.URL.Query().Get("severity"),before,queryLimit(r,100,500));if err!=nil{s.storeError(w,r,err);return};if events==nil{events=[]protocol.Event{}};s.write(w,http.StatusOK,map[string]any{"events":events})}
func(s *Server)jobs(w http.ResponseWriter,r *http.Request){actor:=getIdentity(r);status:=r.URL.Query().Get("status");if status!=""&&!oneOf(status,"pending","approved","dispatched","completed","cancelled"){s.fail(w,r,http.StatusBadRequest,"invalid job status");return};jobs,err:=s.store.ListJobs(r.Context(),actor.tenantID,r.URL.Query().Get("device_id"),status,queryLimit(r,100,250));if err!=nil{s.storeError(w,r,err);return};if jobs==nil{jobs=[]store.Job{}};s.write(w,http.StatusOK,map[string]any{"jobs":jobs})}

type createEnrollmentTokenRequest struct{ExpiresAt time.Time `json:"expires_at"`}
func(s *Server)createEnrollmentToken(w http.ResponseWriter,r *http.Request){actor:=getIdentity(r);if actor.role!="admin"{s.fail(w,r,http.StatusForbidden,"admin role required");return};var input createEnrollmentTokenRequest;if !s.decode(w,r,&input){return};now:=s.now().UTC();if input.ExpiresAt.IsZero(){input.ExpiresAt=now.Add(time.Hour)};if !input.ExpiresAt.After(now)||input.ExpiresAt.After(now.Add(24*time.Hour)){s.fail(w,r,http.StatusBadRequest,"token expiry must be within 24 hours");return};secret:=make([]byte,32);if _,err:=rand.Read(secret);err!=nil{s.internal(w,r,err);return};token:=base64.RawURLEncoding.EncodeToString(secret);if err:=s.store.CreateEnrollmentToken(r.Context(),actor.tenantID,store.HashEnrollmentToken(token),input.ExpiresAt);err!=nil{s.storeError(w,r,err);return};s.auditEvent(r,actor.tenantID,actor.actor,"enrollment_token.created","tenant",actor.tenantID,map[string]any{"expires_at":input.ExpiresAt});s.write(w,http.StatusCreated,map[string]any{"token":token,"expires_at":input.ExpiresAt})}

type createJobRequest struct{DeviceID string `json:"device_id"`;Action string `json:"action"`;Parameters json.RawMessage `json:"parameters"`;Risk string `json:"risk"`;ExpiresAt time.Time `json:"expires_at"`}
var actionRisk=map[string]string{"service.restart":"medium","temp.cleanup":"medium","device.reboot":"high","software.install":"high","software.remove":"high","patch.install":"high"}
var serviceNamePattern=regexp.MustCompile(`^[A-Za-z0-9_.@-]{1,128}$`)
var packageNamePattern=regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.+_-]{0,127}$`)
var packageVersionPattern=regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.+:~_-]{0,127}$`)
func(s *Server)createJob(w http.ResponseWriter,r *http.Request){actor:=getIdentity(r);if actor.role!="technician"&&actor.role!="admin"{s.fail(w,r,http.StatusForbidden,"technician role required");return};var input createJobRequest;if !s.decode(w,r,&input){return};requiredRisk,ok:=actionRisk[input.Action];if !ok||input.DeviceID==""{s.fail(w,r,http.StatusBadRequest,"unsupported or invalid job");return};if err:=validateActionParameters(input.Action,input.Parameters);err!=nil{s.fail(w,r,http.StatusBadRequest,err.Error());return};if input.Risk==""{input.Risk=requiredRisk};if input.Risk!=requiredRisk{s.fail(w,r,http.StatusBadRequest,"risk does not match action catalog");return};now:=s.now().UTC();if input.ExpiresAt.IsZero(){input.ExpiresAt=now.Add(30*time.Minute)};if !input.ExpiresAt.After(now)||input.ExpiresAt.After(now.Add(24*time.Hour)){s.fail(w,r,http.StatusBadRequest,"job expiry must be within 24 hours");return}
	jobID,err:=security.NewID();if err!=nil{s.internal(w,r,err);return};nonceID,err:=security.NewID();if err!=nil{s.internal(w,r,err);return};status:="pending";approvedBy:="";signature:=""
	jobInput:=store.NewJob{ID:jobID,TenantID:actor.tenantID,DeviceID:input.DeviceID,Action:input.Action,Risk:input.Risk,Parameters:input.Parameters,IssuedAt:now,ExpiresAt:input.ExpiresAt,Nonce:nonceID,RequestedBy:actor.actor,Status:status}
	if input.Risk=="low"{status="approved";approvedBy="policy:auto-low-risk";envelope:=jobEnvelope(jobInput,approvedBy);if err:=s.signer.Sign(&envelope);err!=nil{s.internal(w,r,err);return};signature=envelope.Signature;jobInput.Status=status;jobInput.ApprovedBy=approvedBy;jobInput.Signature=signature}
	job,err:=s.store.CreateJob(r.Context(),jobInput);if err!=nil{s.storeError(w,r,err);return};s.auditEvent(r,actor.tenantID,actor.actor,"job.created","job",jobID,map[string]any{"action":input.Action,"device_id":input.DeviceID,"status":status});s.write(w,http.StatusCreated,job)
}
func(s *Server)approveJob(w http.ResponseWriter,r *http.Request){actor:=getIdentity(r);if actor.role!="approver"&&actor.role!="admin"{s.fail(w,r,http.StatusForbidden,"approver role required");return};job,err:=s.store.GetJob(r.Context(),actor.tenantID,r.PathValue("id"));if err!=nil{s.storeError(w,r,err);return};if job.Status!="pending"||!job.Envelope.ExpiresAt.After(s.now()){s.fail(w,r,http.StatusConflict,"job is not approvable");return};job.Envelope.ApprovedBy=actor.actor;if err:=s.signer.Sign(&job.Envelope);err!=nil{s.internal(w,r,err);return};job,err=s.store.ApproveJob(r.Context(),actor.tenantID,job.Envelope.ID,actor.actor,job.Envelope.Signature);if err!=nil{s.storeError(w,r,err);return};s.auditEvent(r,actor.tenantID,actor.actor,"job.approved","job",job.Envelope.ID,map[string]any{"requested_by":job.RequestedBy});s.write(w,http.StatusOK,job)}
func(s *Server)audit(w http.ResponseWriter,r *http.Request){actor:=getIdentity(r);events,err:=s.store.ListAudit(r.Context(),actor.tenantID,queryLimit(r,100,250));if err!=nil{s.internal(w,r,err);return};s.write(w,http.StatusOK,map[string]any{"audit_events":events})}

func jobEnvelope(j store.NewJob,approvedBy string)protocol.JobEnvelope{return protocol.JobEnvelope{ID:j.ID,TenantID:j.TenantID,DeviceID:j.DeviceID,IssuedAt:j.IssuedAt,ExpiresAt:j.ExpiresAt,Nonce:j.Nonce,Action:j.Action,Parameters:j.Parameters,Risk:j.Risk,ApprovedBy:approvedBy}}
func(s *Server)auditEvent(r *http.Request,tenant,actor,action,targetType,targetID string,details any){id,err:=security.NewID();if err!=nil{return};raw,_:=json.Marshal(details);event:=store.AuditEvent{ID:id,TenantID:tenant,Actor:actor,Action:action,TargetType:targetType,TargetID:targetID,OccurredAt:s.now().UTC(),CorrelationID:correlationID(r),Details:raw};if err:=s.store.AppendAudit(r.Context(),event);err!=nil{s.logger.Error("append audit event","error",err,"correlation_id",correlationID(r))}}
func(s *Server)decode(w http.ResponseWriter,r *http.Request,target any)bool{r.Body=http.MaxBytesReader(w,r.Body,maxBodyBytes);decoder:=json.NewDecoder(r.Body);decoder.DisallowUnknownFields();if err:=decoder.Decode(target);err!=nil{var tooLarge *http.MaxBytesError;if errors.As(err,&tooLarge){s.fail(w,r,http.StatusRequestEntityTooLarge,"request body too large");return false};s.fail(w,r,http.StatusBadRequest,"invalid JSON body");return false};if err:=decoder.Decode(&struct{}{});!errors.Is(err,io.EOF){s.fail(w,r,http.StatusBadRequest,"request body must contain one JSON value");return false};return true}
func(s *Server)write(w http.ResponseWriter,status int,value any){w.WriteHeader(status);_ = json.NewEncoder(w).Encode(value)}
func(s *Server)fail(w http.ResponseWriter,r *http.Request,status int,message string){s.write(w,status,protocol.ErrorResponse{Error:message,CorrelationID:correlationID(r)})}
func(s *Server)internal(w http.ResponseWriter,r *http.Request,err error){s.logger.Error("request failed","error",err,"correlation_id",correlationID(r));s.fail(w,r,http.StatusInternalServerError,"internal server error")}
func(s *Server)storeError(w http.ResponseWriter,r *http.Request,err error){switch{case errors.Is(err,store.ErrNotFound):s.fail(w,r,http.StatusNotFound,"not found");case errors.Is(err,store.ErrConflict):s.fail(w,r,http.StatusConflict,"conflict");default:s.internal(w,r,err)}}
func getIdentity(r *http.Request)identity{return r.Context().Value(identityKey).(identity)}
func correlationID(r *http.Request)string{v,_:=r.Context().Value(correlationKey).(string);return v}
func oneOf(value string,values ...string)bool{for _,candidate:=range values{if value==candidate{return true}};return false}
func queryLimit(r *http.Request,fallback,max int)int{value,err:=strconv.Atoi(r.URL.Query().Get("limit"));if err!=nil||value<1{return fallback};if value>max{return max};return value}
func TokenFingerprint(token string)string{sum:=sha256.Sum256([]byte(token));return fmt.Sprintf("%x",sum[:8])}
func validateActionParameters(action string,raw json.RawMessage)error{decode:=func(target any)error{if len(raw)==0{return errors.New("parameters are required")};decoder:=json.NewDecoder(strings.NewReader(string(raw)));decoder.DisallowUnknownFields();if err:=decoder.Decode(target);err!=nil{return errors.New("invalid action parameters")};if err:=decoder.Decode(&struct{}{});!errors.Is(err,io.EOF){return errors.New("parameters must contain one JSON object")};return nil};switch action{case "service.restart":var value struct{ServiceName string `json:"service_name"`};if err:=decode(&value);err!=nil{return err};if !serviceNamePattern.MatchString(value.ServiceName){return errors.New("invalid service_name")};case "temp.cleanup":var value struct{OlderThanHours int `json:"older_than_hours"`};if err:=decode(&value);err!=nil{return err};if value.OlderThanHours<24||value.OlderThanHours>8760{return errors.New("older_than_hours must be between 24 and 8760")};case "device.reboot":var value struct{DelaySeconds int `json:"delay_seconds"`};if err:=decode(&value);err!=nil{return err};if value.DelaySeconds<0||value.DelaySeconds>3600{return errors.New("delay_seconds must be between 0 and 3600")};case "software.install":var value struct{PackageName string `json:"package_name"`;Version string `json:"version,omitempty"`};if err:=decode(&value);err!=nil{return err};if !packageNamePattern.MatchString(value.PackageName)||value.Version!=""&&!packageVersionPattern.MatchString(value.Version){return errors.New("invalid package name or version")};case "software.remove":var value struct{PackageName string `json:"package_name"`};if err:=decode(&value);err!=nil{return err};if !packageNamePattern.MatchString(value.PackageName){return errors.New("invalid package name")};case "patch.install":var value struct{Packages []string `json:"packages"`};if err:=decode(&value);err!=nil{return err};if len(value.Packages)<1||len(value.Packages)>100{return errors.New("packages must contain between 1 and 100 entries")};for _,name:=range value.Packages{if !packageNamePattern.MatchString(name){return errors.New("invalid package name")}};default:return errors.New("unsupported action")};return nil}
