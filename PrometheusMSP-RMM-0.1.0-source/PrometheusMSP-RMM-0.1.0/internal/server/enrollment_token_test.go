package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/PrometheusMSP/PrometheusMSP-RMM/internal/store"
)

type enrollmentTokenStore struct {
	store.Store
	tenantID string
	hash []byte
	expiresAt time.Time
	audited bool
}

func (s *enrollmentTokenStore) CreateEnrollmentToken(_ context.Context,tenantID string,hash []byte,expiresAt time.Time)error{s.tenantID=tenantID;s.hash=append([]byte(nil),hash...);s.expiresAt=expiresAt;return nil}
func (s *enrollmentTokenStore) AppendAudit(_ context.Context,_ store.AuditEvent)error{s.audited=true;return nil}

func TestCreateEnrollmentTokenReturnsSecretOnceAndStoresHash(t *testing.T){
	now:=time.Date(2026,10,16,12,0,0,0,time.UTC);database:=&enrollmentTokenStore{};server:=&Server{store:database,now:func()time.Time{return now}}
	body:=bytes.NewBufferString(`{"expires_at":"2026-10-16T14:00:00Z"}`);request:=httptest.NewRequest("POST","/api/v1/enrollment-tokens",body);request=request.WithContext(context.WithValue(request.Context(),identityKey,identity{tenantID:"tenant-a",actor:"alice",role:"admin"}));response:=httptest.NewRecorder()
	server.createEnrollmentToken(response,request);if response.Code!=201{t.Fatalf("status=%d body=%s",response.Code,response.Body.String())}
	var payload struct{Token string `json:"token"`;ExpiresAt time.Time `json:"expires_at"`};if err:=json.Unmarshal(response.Body.Bytes(),&payload);err!=nil{t.Fatal(err)};if len(payload.Token)<32{t.Fatal("returned token is too short")};sum:=sha256.Sum256([]byte(payload.Token));if !bytes.Equal(database.hash,sum[:]){t.Fatal("store did not receive token hash")};if database.tenantID!="tenant-a"{t.Fatalf("tenant=%q",database.tenantID)};if !database.expiresAt.Equal(payload.ExpiresAt){t.Fatal("expiry mismatch")};if !database.audited{t.Fatal("token creation was not audited")}
}
