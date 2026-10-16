#Requires -RunAsAdministrator
[CmdletBinding()]
param(
  [Parameter(Mandatory)][string]$ServerUrl,
  [Parameter(Mandatory)][SecureString]$EnrollmentToken,
  [string]$BootstrapCAFile,
  [string]$BinaryPath = ".\dist\prometheus-rmm-agent-windows-amd64.exe"
)
$ErrorActionPreference = 'Stop'
$installDir = Join-Path $env:ProgramFiles 'PrometheusRMM'
$stateDir = Join-Path $env:ProgramData 'PrometheusRMM'
New-Item -ItemType Directory -Force -Path $installDir, $stateDir | Out-Null
Copy-Item -Force $BinaryPath (Join-Path $installDir 'prometheus-rmm-agent.exe')
$token = [System.Net.NetworkCredential]::new('', $EnrollmentToken).Password
$acl = Get-Acl $stateDir
$acl.SetAccessRuleProtection($true, $false)
$acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new('SYSTEM','FullControl','ContainerInherit,ObjectInherit','None','Allow'))
$acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new('BUILTIN\Administrators','FullControl','ContainerInherit,ObjectInherit','None','Allow'))
Set-Acl $stateDir $acl
$exe = Join-Path $installDir 'prometheus-rmm-agent.exe'
if (Get-Service PrometheusRMMAgent -ErrorAction SilentlyContinue) { Stop-Service PrometheusRMMAgent; sc.exe delete PrometheusRMMAgent | Out-Null }
New-Service -Name PrometheusRMMAgent -BinaryPathName ('"{0}"' -f $exe) -DisplayName 'Prometheus MSP RMM Agent' -StartupType Automatic
$serviceKey = 'HKLM:\SYSTEM\CurrentControlSet\Services\PrometheusRMMAgent'
$environment = @(
  "PROMETHEUS_SERVER_URL=$ServerUrl",
  "PROMETHEUS_ENROLLMENT_TOKEN=$token",
  "PROMETHEUS_STATE_DIR=$stateDir",
  'PROMETHEUS_DRY_RUN=true'
)
if ($BootstrapCAFile) {
  $caPath = Join-Path $stateDir 'bootstrap-ca.crt'
  Copy-Item -Force $BootstrapCAFile $caPath
  $environment += "PROMETHEUS_BOOTSTRAP_CA_FILE=$caPath"
}
New-ItemProperty -Path $serviceKey -Name Environment -PropertyType MultiString -Value $environment -Force | Out-Null
Start-Service PrometheusRMMAgent
$token = $null
