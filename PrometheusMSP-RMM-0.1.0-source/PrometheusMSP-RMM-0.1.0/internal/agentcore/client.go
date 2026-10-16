package agentcore

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"

	"github.com/PrometheusMSP/PrometheusMSP-RMM/internal/protocol"
)

const apiPrefix = "/api/v1/agent"

type APIClient struct { base string; http *http.Client }

func NewBootstrapClient(cfg Config) (*APIClient,error) {
	roots,err:=x509.SystemCertPool();if err!=nil||roots==nil{roots=x509.NewCertPool()}
	if cfg.BootstrapCAFile!=""{b,e:=os.ReadFile(cfg.BootstrapCAFile);if e!=nil{return nil,fmt.Errorf("read bootstrap CA: %w",e)};if !roots.AppendCertsFromPEM(b){return nil,errors.New("bootstrap CA file contains no valid certificates")}}
	return &APIClient{base: cfg.ServerURL, http: &http.Client{Timeout: cfg.RequestTimeout, Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13,RootCAs:roots}}}},nil
}

func NewAuthenticatedClient(cfg Config, id *Identity) (*APIClient, error) {
	cert, err := tls.X509KeyPair([]byte(id.CertificatePEM), []byte(id.PrivateKeyPEM)); if err != nil { return nil, fmt.Errorf("load client certificate: %w", err) }
	roots, err := x509.SystemCertPool(); if err != nil || roots == nil { roots = x509.NewCertPool() }
	if id.CACertificatePEM != "" && !roots.AppendCertsFromPEM([]byte(id.CACertificatePEM)) { return nil, errors.New("invalid CA certificate") }
	tr := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}, RootCAs: roots}}
	return &APIClient{base: cfg.ServerURL, http: &http.Client{Timeout: cfg.RequestTimeout, Transport: tr}}, nil
}

func (c *APIClient) Enroll(ctx context.Context, cfg Config, publicKey string) (*protocol.EnrollmentResponse, error) {
	req := protocol.EnrollmentRequest{Token: cfg.EnrollmentToken, Name: cfg.Hostname, Platform: runtime.GOOS, PublicKey: publicKey, AgentVersion: AgentVersion}
	var out protocol.EnrollmentResponse
	if err := c.do(ctx, http.MethodPost, apiPrefix+"/enroll", req, &out); err != nil { return nil, err }
	if out.DeviceID == "" || out.TenantID == "" || out.CertificatePEM == "" || out.ServerSigningKey == "" { return nil, errors.New("enrollment response is incomplete") }
	return &out, nil
}

func (c *APIClient) Heartbeat(ctx context.Context, v protocol.Heartbeat) error { return c.do(ctx,http.MethodPost,apiPrefix+"/heartbeat",v,nil) }
func (c *APIClient) UploadInventory(ctx context.Context, v protocol.Inventory) error { return c.do(ctx,http.MethodPost,apiPrefix+"/inventory",v,nil) }
func (c *APIClient) UploadEvents(ctx context.Context, v protocol.EventBatch) error { return c.do(ctx,http.MethodPost,apiPrefix+"/events",v,nil) }
func (c *APIClient) SubmitResult(ctx context.Context, v protocol.JobResult) error { return c.do(ctx,http.MethodPost,apiPrefix+"/jobs/"+v.JobID+"/results",v,nil) }
func (c *APIClient) PollJobs(ctx context.Context) ([]protocol.JobEnvelope, error) {
	var raw json.RawMessage; if err := c.do(ctx,http.MethodGet,apiPrefix+"/jobs",nil,&raw); err != nil{return nil,err}
	var jobs []protocol.JobEnvelope; if json.Unmarshal(raw,&jobs)==nil{return jobs,nil}
	var wrapper struct{Jobs []protocol.JobEnvelope `json:"jobs"`}; if err:=json.Unmarshal(raw,&wrapper);err!=nil{return nil,fmt.Errorf("decode jobs: %w",err)};return wrapper.Jobs,nil
}

func (c *APIClient) do(ctx context.Context, method,path string, in,out any) error {
	var body io.Reader
	if in != nil { b,e:=json.Marshal(in);if e!=nil{return e};body=bytes.NewReader(b) }
	req,e:=http.NewRequestWithContext(ctx,method,c.base+path,body);if e!=nil{return e}
	req.Header.Set("Accept","application/json");req.Header.Set("X-Correlation-ID",correlationID());if in!=nil{req.Header.Set("Content-Type","application/json")}
	resp,e:=c.http.Do(req);if e!=nil{return e};defer resp.Body.Close()
	b,e:=io.ReadAll(io.LimitReader(resp.Body,4<<20));if e!=nil{return e}
	if resp.StatusCode<200||resp.StatusCode>=300{return fmt.Errorf("API %s %s returned %d: %s",method,path,resp.StatusCode,string(b))}
	if out!=nil&&len(b)>0 { if p,ok:=out.(*json.RawMessage);ok{*p=append((*p)[:0],b...);return nil}; if e=json.Unmarshal(b,out);e!=nil{return e} }
	return nil
}

func correlationID() string { var b [16]byte; _,_=randRead(b[:]);return hex.EncodeToString(b[:]) }

func (c *APIClient) CloseIdleConnections() { c.http.CloseIdleConnections() }
