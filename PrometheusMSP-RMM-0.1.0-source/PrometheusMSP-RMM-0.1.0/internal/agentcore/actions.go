package agentcore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/PrometheusMSP/PrometheusMSP-RMM/internal/protocol"
)

const ( ActionServiceRestart="service.restart"; ActionTempCleanup="temp.cleanup"; ActionControlledReboot="device.reboot"; ActionSoftwareInstall="software.install"; ActionSoftwareRemove="software.remove"; ActionPatchInstall="patch.install" )
var serviceNameRE=regexp.MustCompile(`^[A-Za-z0-9_.@-]{1,128}$`)
var packageNameRE=regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.+_-]{0,127}$`)
var packageVersionRE=regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.+:~_-]{0,127}$`)

type ActionExecutor interface { RestartService(context.Context,string,bool)(string,error); Reboot(context.Context,time.Duration,bool)(string,error); InstallSoftware(context.Context,string,string,bool)(string,error); RemoveSoftware(context.Context,string,bool)(string,error); InstallPatches(context.Context,[]string,bool)(string,error) }
type Policy struct { services,packages map[string]struct{}; AllowTempCleanup,AllowReboot,AllowSoftware,AllowPatching,DryRun bool; ActionTimeout time.Duration; TempDir string; Now func()time.Time }
func NewPolicy(cfg Config)*Policy{m:=map[string]struct{}{};for _,s:=range cfg.AllowedServices{m[strings.ToLower(s)]=struct{}{}};pkgs:=map[string]struct{}{};for _,s:=range cfg.AllowedPackages{pkgs[strings.ToLower(s)]=struct{}{}};timeout:=cfg.ActionTimeout;if timeout<=0{timeout=30*time.Minute};return &Policy{services:m,packages:pkgs,AllowTempCleanup:cfg.AllowTempCleanup,AllowReboot:cfg.AllowReboot,AllowSoftware:cfg.AllowSoftware,AllowPatching:cfg.AllowPatching,DryRun:cfg.DryRun,ActionTimeout:timeout,TempDir:os.TempDir(),Now:time.Now}}

func (p *Policy) Execute(ctx context.Context, x ActionExecutor, j protocol.JobEnvelope)(string,error){
	if j.ApprovedBy=="" { return "",errors.New("job lacks technician approval") }
	expectedRisk:=map[string]string{ActionServiceRestart:"medium",ActionTempCleanup:"medium",ActionControlledReboot:"high",ActionSoftwareInstall:"high",ActionSoftwareRemove:"high",ActionPatchInstall:"high"}
	if risk,ok:=expectedRisk[j.Action];!ok||j.Risk!=risk{return "",errors.New("job risk does not match the local action catalog")}
	switch j.Action {
	case ActionServiceRestart:
		var v struct{ServiceName string `json:"service_name"`};if e:=strictParams(j.Parameters,&v);e!=nil{return "",e};if !serviceNameRE.MatchString(v.ServiceName){return "",errors.New("invalid service name")};if _,ok:=p.services[strings.ToLower(v.ServiceName)];!ok{return "",errors.New("service is not locally allowlisted")};return x.RestartService(ctx,v.ServiceName,p.DryRun)
	case ActionTempCleanup:
		if !p.AllowTempCleanup{return "",errors.New("temporary-file cleanup is disabled by local policy")};var v struct{OlderThanHours int `json:"older_than_hours"`};if e:=strictParams(j.Parameters,&v);e!=nil{return "",e};if v.OlderThanHours<24||v.OlderThanHours>8760{return "",errors.New("older_than_hours must be between 24 and 8760")};return cleanupTemp(p.TempDir,p.Now().Add(-time.Duration(v.OlderThanHours)*time.Hour),p.DryRun)
	case ActionControlledReboot:
		if !p.AllowReboot{return "",errors.New("reboot is disabled by local policy")};var v struct{DelaySeconds int `json:"delay_seconds"`};if e:=strictParams(j.Parameters,&v);e!=nil{return "",e};if v.DelaySeconds<0||v.DelaySeconds>3600{return "",errors.New("delay_seconds must be between 0 and 3600")};return x.Reboot(ctx,time.Duration(v.DelaySeconds)*time.Second,p.DryRun)
	case ActionSoftwareInstall:
		if !p.AllowSoftware{return "",errors.New("software management is disabled by local policy")};var v struct{PackageName string `json:"package_name"`;Version string `json:"version,omitempty"`};if e:=strictParams(j.Parameters,&v);e!=nil{return "",e};if e:=p.validatePackage(v.PackageName);e!=nil{return "",e};if v.Version!=""&&!packageVersionRE.MatchString(v.Version){return "",errors.New("invalid package version")};actionCtx,cancel:=context.WithTimeout(ctx,p.ActionTimeout);defer cancel();return x.InstallSoftware(actionCtx,v.PackageName,v.Version,p.DryRun)
	case ActionSoftwareRemove:
		if !p.AllowSoftware{return "",errors.New("software management is disabled by local policy")};var v struct{PackageName string `json:"package_name"`};if e:=strictParams(j.Parameters,&v);e!=nil{return "",e};if e:=p.validatePackage(v.PackageName);e!=nil{return "",e};actionCtx,cancel:=context.WithTimeout(ctx,p.ActionTimeout);defer cancel();return x.RemoveSoftware(actionCtx,v.PackageName,p.DryRun)
	case ActionPatchInstall:
		if !p.AllowPatching{return "",errors.New("patching is disabled by local policy")};var v struct{Packages []string `json:"packages"`};if e:=strictParams(j.Parameters,&v);e!=nil{return "",e};if len(v.Packages)==0||len(v.Packages)>100{return "",errors.New("packages must contain between 1 and 100 entries")};for _,name:=range v.Packages{if e:=p.validatePackage(name);e!=nil{return "",e}};actionCtx,cancel:=context.WithTimeout(ctx,p.ActionTimeout);defer cancel();return x.InstallPatches(actionCtx,v.Packages,p.DryRun)
	default:return "",fmt.Errorf("action %q is not supported",j.Action)
	}
}
func(p *Policy)validatePackage(name string)error{if !packageNameRE.MatchString(name){return errors.New("invalid package name")};if _,ok:=p.packages[strings.ToLower(name)];!ok{return errors.New("package is not locally allowlisted")};return nil}
func strictParams(b []byte,v any)error{if len(b)==0{return errors.New("parameters are required")};d:=json.NewDecoder(strings.NewReader(string(b)));d.DisallowUnknownFields();if e:=d.Decode(v);e!=nil{return fmt.Errorf("invalid parameters: %w",e)};var extra any;if e:=d.Decode(&extra);!errors.Is(e,io.EOF){return errors.New("multiple parameter values")};return nil}
func cleanupTemp(root string,before time.Time,dry bool)(string,error){root=filepath.Clean(root);if root=="."||root==string(filepath.Separator){return "",errors.New("unsafe temporary directory")};removed:=0;var bytes int64;e:=filepath.WalkDir(root,func(path string,d fs.DirEntry,e error)error{if e!=nil{return e};if path==root||d.IsDir()||d.Type()&os.ModeSymlink!=0{return nil};info,e:=d.Info();if e!=nil{return e};if !info.ModTime().Before(before){return nil};if !dry{if e:=os.Remove(path);e!=nil{return e}};removed++;bytes+=info.Size();return nil});if e!=nil{return "",e};return fmt.Sprintf("temporary cleanup: files=%d bytes=%d dry_run=%t",removed,bytes,dry),nil}
