package agentcore

import (
	"context"
	"net"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/PrometheusMSP/PrometheusMSP-RMM/internal/protocol"
)

type Collector struct{ platform *Platform }
func NewCollector(p *Platform)*Collector{return &Collector{platform:p}}
func(c *Collector)Inventory(ctx context.Context,deviceID string)(protocol.Inventory,error){host,_:=os.Hostname();oi,hw,disks,services,software,processes:=c.platform.details(ctx);inv:=protocol.Inventory{SchemaVersion:protocol.SchemaVersion,DeviceID:deviceID,CollectedAt:time.Now().UTC(),Hostname:host,OS:oi,Hardware:hw,Disks:disks,Services:services,Software:software,Processes:processes};ifs,_:=net.Interfaces();for _,i:=range ifs{n:=protocol.NetworkInfo{Name:i.Name,MAC:i.HardwareAddr.String()};as,_:=i.Addrs();for _,a:=range as{n.Addresses=append(n.Addresses,a.String())};inv.Networks=append(inv.Networks,n)};return inv,nil}
func(c *Collector)Events(ctx context.Context,deviceID string)(protocol.EventBatch,error){return c.platform.events(ctx,deviceID)}
func(c *Collector)Uptime()uint64{return c.platform.uptime()}
func runtimeArch()string{return runtime.GOARCH}
func runtimeCPUs()int{return runtime.NumCPU()}
func bounded(s string)string{const max=64<<10;s=strings.TrimSpace(s);if len(s)>max{return s[:max]+" [truncated]"};return s}
func asString(v any)string{if s,ok:=v.(string);ok{return s};return""}
