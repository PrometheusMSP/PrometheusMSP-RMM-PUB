//go:build linux

package agentcore

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/PrometheusMSP/PrometheusMSP-RMM/internal/protocol"
)

type Platform struct{ checkpoint,checkpointPath string }
func NewPlatform(stateDir string) *Platform{p:=&Platform{checkpointPath:filepath.Join(stateDir,"event-checkpoint")};if b,e:=os.ReadFile(p.checkpointPath);e==nil{p.checkpoint=strings.TrimSpace(string(b))};return p}
func (p *Platform) RestartService(ctx context.Context,name string,dry bool)(string,error){if dry{return "would restart service "+name,nil};b,e:=exec.CommandContext(ctx,"systemctl","restart",name).CombinedOutput();return bounded(string(b)),e}
func (p *Platform) Reboot(ctx context.Context,delay time.Duration,dry bool)(string,error){if dry{return fmt.Sprintf("would reboot after %s",delay),nil};minutes:=int((delay+time.Minute-1)/time.Minute);b,e:=exec.CommandContext(ctx,"shutdown","-r",fmt.Sprintf("+%d",minutes),"Prometheus RMM approved reboot").CombinedOutput();return bounded(string(b)),e}
func(p *Platform)InstallSoftware(ctx context.Context,name,version string,dry bool)(string,error){manager,e:=packageManager();if e!=nil{return "",e};spec:=name;if version!=""{if filepath.Base(manager)=="apt-get"{spec=name+"="+version}else{spec=name+"-"+version}};args:=packageArgs(manager,"install",[]string{spec});if dry{return "would run "+manager+" "+strings.Join(args," "),nil};b,e:=exec.CommandContext(ctx,manager,args...).CombinedOutput();return bounded(string(b)),e}
func(p *Platform)RemoveSoftware(ctx context.Context,name string,dry bool)(string,error){manager,e:=packageManager();if e!=nil{return "",e};args:=packageArgs(manager,"remove",[]string{name});if dry{return "would run "+manager+" "+strings.Join(args," "),nil};b,e:=exec.CommandContext(ctx,manager,args...).CombinedOutput();return bounded(string(b)),e}
func(p *Platform)InstallPatches(ctx context.Context,names []string,dry bool)(string,error){manager,e:=packageManager();if e!=nil{return "",e};args:=packageArgs(manager,"patch",names);if dry{return "would run "+manager+" "+strings.Join(args," "),nil};b,e:=exec.CommandContext(ctx,manager,args...).CombinedOutput();return bounded(string(b)),e}
func packageManager()(string,error){for _,name:=range []string{"apt-get","dnf","yum","zypper"}{if p,e:=exec.LookPath(name);e==nil{return p,nil}};return "",errors.New("no supported package manager found")}
func packageArgs(manager,operation string,names []string)[]string{base:=filepath.Base(manager);switch base{case"apt-get":if operation=="patch"{return append([]string{"-y","--only-upgrade","install"},names...)};return append([]string{"-y",operation},names...);case"zypper":op:=operation;if operation=="patch"{op="update"};return append([]string{"--non-interactive",op},names...);default:op:=operation;if operation=="patch"{op="upgrade"};return append([]string{"-y",op},names...)}}
func (p *Platform) details(ctx context.Context)(protocol.OSInfo,protocol.HardwareInfo,[]protocol.DiskInfo,[]protocol.ServiceInfo,[]protocol.SoftwareInfo,[]protocol.ProcessInfo){
	osinfo:=protocol.OSInfo{Name:"Linux",Architecture:runtimeArch()};if b,e:=os.ReadFile("/etc/os-release");e==nil{m:=parseKV(string(b));osinfo.Name=strings.Trim(m["PRETTY_NAME"],`"`);osinfo.Version=strings.Trim(m["VERSION_ID"],`"`)}
	hw:=protocol.HardwareInfo{CPUs:runtimeCPUs()};if f,e:=os.Open("/proc/meminfo");e==nil{defer f.Close();s:=bufio.NewScanner(f);for s.Scan(){var kb uint64;if _,e:=fmt.Sscanf(s.Text(),"MemTotal: %d kB",&kb);e==nil&&kb>0{hw.MemoryBytes=kb*1024;break}}};if b,e:=os.ReadFile("/etc/machine-id");e==nil{hw.MachineID=strings.TrimSpace(string(b))}
	var st syscall.Statfs_t;var disks []protocol.DiskInfo;if syscall.Statfs("/",&st)==nil{disks=[]protocol.DiskInfo{{Path:"/",TotalBytes:st.Blocks*uint64(st.Bsize),FreeBytes:st.Bavail*uint64(st.Bsize)}}};return osinfo,hw,disks,linuxServices(ctx),linuxSoftware(ctx),linuxProcesses()
}
func linuxProcesses()[]protocol.ProcessInfo{entries,e:=os.ReadDir("/proc");if e!=nil{return nil};out:=make([]protocol.ProcessInfo,0,128);for _,entry:=range entries{if len(out)>=500{break};pid,e:=strconv.Atoi(entry.Name());if e!=nil||!entry.IsDir(){continue};b,e:=os.ReadFile(filepath.Join("/proc",entry.Name(),"comm"));if e==nil{out=append(out,protocol.ProcessInfo{PID:pid,Name:strings.TrimSpace(string(b))})}};return out}
func linuxServices(ctx context.Context)[]protocol.ServiceInfo{commandCtx,cancel:=context.WithTimeout(ctx,10*time.Second);defer cancel();b,e:=exec.CommandContext(commandCtx,"systemctl","list-units","--type=service","--all","--no-legend","--no-pager").Output();if e!=nil{return nil};var out []protocol.ServiceInfo;for _,line:=range strings.Split(string(b),"\n"){if len(out)>=500{break};fields:=strings.Fields(line);if len(fields)>0&&fields[0]=="●"{fields=fields[1:]};if len(fields)>=4{out=append(out,protocol.ServiceInfo{Name:fields[0],Status:fields[3]})}};return out}
func linuxSoftware(ctx context.Context)[]protocol.SoftwareInfo{commandCtx,cancel:=context.WithTimeout(ctx,15*time.Second);defer cancel();var b []byte;var e error;if _,look:=exec.LookPath("dpkg-query");look==nil{b,e=exec.CommandContext(commandCtx,"dpkg-query","-W","-f=${Package}\\t${Version}\\n").Output()}else if _,look:=exec.LookPath("rpm");look==nil{b,e=exec.CommandContext(commandCtx,"rpm","-qa","--qf","%{NAME}\\t%{VERSION}-%{RELEASE}\\n").Output()}else{return nil};if e!=nil{return nil};var out []protocol.SoftwareInfo;for _,line:=range strings.Split(string(b),"\n"){if len(out)>=500{break};fields:=strings.SplitN(line,"\t",2);if len(fields)==2{out=append(out,protocol.SoftwareInfo{Name:fields[0],Version:fields[1]})}};return out}
func (p *Platform) uptime()uint64{b,e:=os.ReadFile("/proc/uptime");if e!=nil{return 0};f,_:=strconv.ParseFloat(strings.Fields(string(b))[0],64);return uint64(f)}
func (p *Platform) events(ctx context.Context,deviceID string)(protocol.EventBatch,error){args:=[]string{"--no-pager","-n","100","-o","json"};if p.checkpoint!=""{args=append(args,"--after-cursor",p.checkpoint)};b,e:=exec.CommandContext(ctx,"journalctl",args...).Output();if e!=nil{return protocol.EventBatch{Checkpoint:p.checkpoint},nil};batch:=protocol.EventBatch{Checkpoint:p.checkpoint};for _,line:=range strings.Split(string(b),"\n"){if line==""{continue};var x map[string]any;if json.Unmarshal([]byte(line),&x)!=nil{continue};cursor:=asString(x["__CURSOR"]);micros,_:=strconv.ParseInt(asString(x["__REALTIME_TIMESTAMP"]),10,64);ev:=protocol.Event{ID:cursor,SchemaVersion:protocol.SchemaVersion,DeviceID:deviceID,OccurredAt:time.UnixMicro(micros),Source:"journald",Severity:journalSeverity(asString(x["PRIORITY"])),Provider:asString(x["SYSLOG_IDENTIFIER"]),Message:asString(x["MESSAGE"])};batch.Events=append(batch.Events,ev);if cursor!=""{batch.Checkpoint=cursor}};p.checkpoint=batch.Checkpoint;if p.checkpoint!=""{_ = os.WriteFile(p.checkpointPath,[]byte(p.checkpoint+"\n"),0600)};return batch,nil}
func parseKV(s string)map[string]string{m:=map[string]string{};for _,l:=range strings.Split(s,"\n"){if a:=strings.SplitN(l,"=",2);len(a)==2{m[a[0]]=a[1]}};return m}
func journalSeverity(p string)string{switch p{case"0","1","2","3":return"error";case"4":return"warning";default:return"info"}}
