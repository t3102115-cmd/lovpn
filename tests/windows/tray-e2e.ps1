# Real-desktop check of lovpn-tray.exe. Must run in the INTERACTIVE session of a logged-on
# administrator (a scheduled task with /IT and /RL HIGHEST), because a tray icon exists only
# in a desktop session. It starts and stops the real LoVPNClient service to produce the
# state changes, so run it only on the disposable test VM.
#   tray-e2e.ps1 -Tray C:\lovpn\target\debug\lovpn-tray.exe -Out C:\Users\silvan\tray-result
param([Parameter(Mandatory)][string]$Tray, [Parameter(Mandatory)][string]$Out)
$ErrorActionPreference = 'Continue'
New-Item -ItemType Directory -Force $Out | Out-Null
$log = Join-Path $Out 'result.txt'
Remove-Item $log -ErrorAction SilentlyContinue
function Say($m) { Add-Content $log $m; }
function Check($ok, $what) { Say ($(if ($ok) { 'PASS: ' } else { 'FAIL: ' }) + $what) }
Add-Type -AssemblyName System.Windows.Forms, System.Drawing
Add-Type -Namespace W -Name U -MemberDefinition '[System.Runtime.InteropServices.DllImport("user32.dll")] public static extern bool SetProcessDPIAware();'
[W.U]::SetProcessDPIAware() | Out-Null
[System.Windows.Forms.SendKeys]::SendWait('{ESC}')   # close a stray Start menu
function Shot($name) {
  $b = [System.Windows.Forms.SystemInformation]::VirtualScreen
  $bmp = New-Object System.Drawing.Bitmap $b.Width, $b.Height
  $g = [System.Drawing.Graphics]::FromImage($bmp)
  $g.CopyFromScreen($b.Location, [System.Drawing.Point]::Empty, $b.Size)
  $bmp.Save((Join-Path $Out "$name.png")); $g.Dispose(); $bmp.Dispose()
}
function Entry {
  Get-ChildItem 'HKCU:\Control Panel\NotifyIconSettings' -ErrorAction SilentlyContinue |
    Where-Object { (Get-ItemProperty $_.PSPath).ExecutablePath -like '*lovpn-tray.exe' }
}

Get-Process lovpn-tray -ErrorAction SilentlyContinue | Stop-Process -Force
sc.exe stop LoVPNClient | Out-Null; Start-Sleep 3
Say ("session id: " + (Get-Process -Id $PID).SessionId)

$p = Start-Process $Tray -PassThru; Start-Sleep 6
Check (-not $p.HasExited) 'tray starts and keeps running in the desktop session'
$e = Entry
Check ($null -ne $e) 'Windows registered a notification-area icon for lovpn-tray.exe'
if ($e) { Set-ItemProperty $e.PSPath -Name IsPromoted -Value 1 -Type DWord -ErrorAction SilentlyContinue }
$second = Start-Process $Tray -PassThru; $second.WaitForExit(8000) | Out-Null
Check $second.HasExited 'a second tray exits at once (one icon per session)'
Start-Sleep 2; Shot 'service-down'

sc.exe start LoVPNClient | Out-Null; Start-Sleep 10; Shot 'service-up'
sc.exe stop LoVPNClient | Out-Null
Start-Sleep 8; Shot 'balloon-1'; Start-Sleep 3; Shot 'balloon-2'
Check (-not $p.HasExited) 'tray survives the service stopping'
$p.CloseMainWindow() | Out-Null
Stop-Process $p -Force -ErrorAction SilentlyContinue
Say 'done'
