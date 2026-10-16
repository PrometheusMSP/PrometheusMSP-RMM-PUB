package security

import (
	"net/http/httptest"
	"testing"
)

func TestBearerAuthenticator(t *testing.T) {
	auth:=NewBearerAuthenticator(map[string]Operator{"a-long-random-token-value":{ID:"alice",TenantID:"tenant-a",Role:"admin"}})
	request:=httptest.NewRequest("GET","/",nil);request.Header.Set("Authorization","Bearer a-long-random-token-value")
	operator,err:=auth.Authenticate(request);if err!=nil{t.Fatal(err)};if operator.TenantID!="tenant-a"{t.Fatalf("tenant = %q",operator.TenantID)}
	request.Header.Set("Authorization","Bearer wrong");if _,err:=auth.Authenticate(request);err==nil{t.Fatal("invalid bearer token was accepted")}
}
