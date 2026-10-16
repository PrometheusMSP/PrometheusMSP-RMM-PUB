package server

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"testing"
)

func TestValidateActionParameters(t *testing.T) {
	tests:=[]struct{name,action,parameters string;valid bool}{
		{"service","service.restart",`{"service_name":"sshd.service"}`,true},
		{"unsafe service","service.restart",`{"service_name":"sshd; reboot"}`,false},
		{"unknown field","service.restart",`{"service_name":"sshd","command":"x"}`,false},
		{"cleanup min","temp.cleanup",`{"older_than_hours":24}`,true},
		{"cleanup too young","temp.cleanup",`{"older_than_hours":23}`,false},
		{"reboot immediate","device.reboot",`{"delay_seconds":0}`,true},
		{"reboot too late","device.reboot",`{"delay_seconds":3601}`,false},
		{"software install","software.install",`{"package_name":"openssl","version":"3.0.1-1"}`,true},
		{"software shell input","software.install",`{"package_name":"openssl;id"}`,false},
		{"software remove extra","software.remove",`{"package_name":"openssl","force":true}`,false},
		{"patches","patch.install",`{"packages":["openssl","curl"]}`,true},
		{"empty patches","patch.install",`{"packages":[]}`,false},
		{"unsupported","script.run",`{}`,false},
	}
	for _,test:=range tests{t.Run(test.name,func(t *testing.T){err:=validateActionParameters(test.action,json.RawMessage(test.parameters));if test.valid&&err!=nil{t.Fatalf("unexpected error: %v",err)};if !test.valid&&err==nil{t.Fatal("expected validation error")}})}
}

func TestViewerCannotCreateJob(t *testing.T){server:=&Server{};request:=httptest.NewRequest("POST","/api/v1/jobs",nil);request=request.WithContext(context.WithValue(request.Context(),identityKey,identity{tenantID:"tenant-a",actor:"reader",role:"viewer"}));response:=httptest.NewRecorder();server.createJob(response,request);if response.Code!=403{t.Fatalf("status=%d",response.Code)}}
