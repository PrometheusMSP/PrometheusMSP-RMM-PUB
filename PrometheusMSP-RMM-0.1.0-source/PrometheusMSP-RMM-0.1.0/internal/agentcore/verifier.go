package agentcore

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/PrometheusMSP/PrometheusMSP-RMM/internal/protocol"
)

func CanonicalJobBytes(j protocol.JobEnvelope) ([]byte,error) { return j.SigningBytes() }

type ReplayStore struct { path string; mu sync.Mutex; Seen map[string]time.Time `json:"seen"` }
func LoadReplayStore(path string) (*ReplayStore,error) { r:=&ReplayStore{path:path,Seen:map[string]time.Time{}};b,e:=os.ReadFile(path);if errors.Is(e,os.ErrNotExist){return r,nil};if e!=nil{return nil,e};if e=json.Unmarshal(b,r);e!=nil{return nil,e};r.path=path;if r.Seen==nil{r.Seen=map[string]time.Time{}};return r,nil }
func (r *ReplayStore) Consume(nonce string, expires,timeNow time.Time) error { r.mu.Lock();defer r.mu.Unlock();for n,t:=range r.Seen{if t.Before(timeNow){delete(r.Seen,n)}};if _,ok:=r.Seen[nonce];ok{return errors.New("job nonce was already consumed")};r.Seen[nonce]=expires;return r.saveLocked() }
func (r *ReplayStore) saveLocked() error { if e:=os.MkdirAll(filepath.Dir(r.path),0700);e!=nil{return e};b,e:=json.Marshal(r);if e!=nil{return e};tmp:=r.path+".tmp";if e=os.WriteFile(tmp,b,0600);e!=nil{return e};if e=os.Rename(tmp,r.path);e!=nil{_ = os.Remove(tmp);return e};return os.Chmod(r.path,0600) }

type JobVerifier struct { key ed25519.PublicKey; tenantID,deviceID string; replay *ReplayStore; now func()time.Time; maxClockSkew time.Duration }
func NewJobVerifier(signingKey,tenantID,deviceID string,replay *ReplayStore)(*JobVerifier,error){k,e:=parseSigningKey(signingKey);if e!=nil{return nil,e};return &JobVerifier{key:k,tenantID:tenantID,deviceID:deviceID,replay:replay,now:time.Now,maxClockSkew:5*time.Minute},nil}
func (v *JobVerifier) Verify(j protocol.JobEnvelope) error {
	now:=v.now().UTC();if j.ID==""||j.Nonce==""{return errors.New("missing job ID or nonce")};if j.TenantID!=v.tenantID||j.DeviceID!=v.deviceID{return errors.New("job scope does not match this device")};if !j.ExpiresAt.After(now){return errors.New("job has expired")};if !j.ExpiresAt.After(j.IssuedAt){return errors.New("job expiry must follow issue time")};if j.IssuedAt.After(now.Add(v.maxClockSkew)){return errors.New("job issued too far in the future")};if j.ExpiresAt.Sub(j.IssuedAt)>24*time.Hour{return errors.New("job validity exceeds 24 hours")}
	if e:=j.Verify(v.key);e!=nil{return e};return v.replay.Consume(j.Nonce,j.ExpiresAt,now)
}
func parseSigningKey(s string)(ed25519.PublicKey,error){if block,_:=pem.Decode([]byte(s));block!=nil{k,e:=x509.ParsePKIXPublicKey(block.Bytes);if e!=nil{return nil,e};pub,ok:=k.(ed25519.PublicKey);if !ok{return nil,errors.New("server signing key is not Ed25519")};return pub,nil};b,e:=base64.RawURLEncoding.DecodeString(s);if e!=nil||len(b)!=ed25519.PublicKeySize{return nil,fmt.Errorf("invalid Ed25519 server signing key")};return ed25519.PublicKey(b),nil}
