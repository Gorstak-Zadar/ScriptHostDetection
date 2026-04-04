$AgentsAvBin = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..\Bin'))
# Script Host Detection - mshta/wscript/cscript used for RAT/remote execution
# Detects script-host processes with HTTP, encoded, or remote script arguments

param([hashtable]$ModuleConfig)

$ModuleName = "ScriptHostDetection"
$LastTick = Get-Date
$TickInterval = if ($ModuleConfig.TickInterval) { $ModuleConfig.TickInterval } else { 60 }

$ScriptHosts = @('mshta.exe','wscript.exe','cscript.exe','scriptrunner.exe')
$SuspiciousPatterns = @(
    'http[s]?://[^\s''"]+',
    'vbscript:',
    'javascript:',
    '-EncodedCommand',
    '\.hta\b',
    '\.vbs\b.*http|http.*\.vbs',
    '\.js\b.*http|http.*\.js',
    'Execute.*Request|Response\.Write',
    'eval\s*\(|Execute\s*\(',
    'GetObject\s*\(.*http',
    'XMLHTTP|WinHttp|MSXML2\.ServerXMLHTTP',
    'Adodb\.Stream.*TypeBinary|\.Open.*adTypeBinary',
    'ExpandEnvironmentStrings.*%temp%|%appdata%',
    'powershell.*-enc|powershell.*-encodedcommand'
)

function Test-SuspiciousScriptHostCommandLine {
    param([string]$CmdLine)
    if ([string]::IsNullOrWhiteSpace($CmdLine)) { return $false }
    $count = 0
    foreach ($pat in $SuspiciousPatterns) {
        if ($CmdLine -match $pat) { $count++ }
        if ($count -ge 2) { return $true }
    }
    if ($CmdLine -match 'http[s]?://' -and $CmdLine.Length -gt 80) { return $true }
    return $false
}

function Invoke-ScriptHostDetection {
    $detections = @()
    try {
        $procs = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -in $ScriptHosts }
        foreach ($p in $procs) {
            $cmd = $p.CommandLine
            if (-not (Test-SuspiciousScriptHostCommandLine -CmdLine $cmd)) { continue }
            $path = $p.ExecutablePath
            $sig = $null
            if ($path -and (Test-Path $path)) {
                $sig = Get-AuthenticodeSignature -FilePath $path -ErrorAction SilentlyContinue
            }
            $detections += @{
                ProcessId = $p.ProcessId
                ProcessName = $p.Name
                CommandLine = $cmd
                Path = $path
                Signed = ($sig.Status -eq 'Valid')
                Risk = if ($sig -and $sig.Status -ne 'Valid') { "Critical" } else { "High" }
            }
        }

        # Scheduled tasks that launch script hosts with URLs or encoded args
        try {
            $tasks = Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.State -eq 'Ready' }
            foreach ($t in $tasks) {
                $action = $t.Actions | Select-Object -First 1
                $exec = $action.Execute
                $arg = $action.Arguments
                $combined = "$exec $arg"
                if ($exec -notmatch 'mshta|wscript|cscript') { continue }
                if (Test-SuspiciousScriptHostCommandLine -CmdLine $combined) {
                    $detections += @{
                        Type = "Scheduled task script host with suspicious args"
                        TaskName = $t.TaskName
                        Execute = $exec
                        Arguments = $arg
                        Risk = "High"
                    }
                }
            }
        } catch { }

        if ($detections.Count -gt 0) {
            foreach ($d in $detections) {
                $short = if ($d.CommandLine) { $d.CommandLine.Substring(0, [Math]::Min(200, $d.CommandLine.Length)) } else { $d.TaskName -or $d.Arguments }
                $msg = "ScriptHostDetection: $($d.ProcessName -or 'Task') - $short"
                Write-EventLog -LogName Application -Source "AntivirusEDR" -EntryType Warning -EventId 2096 -Message $msg -ErrorAction SilentlyContinue
            }
            $logPath = "$env:ProgramData\Antivirus\Logs\ScriptHostDetection_$(Get-Date -Format 'yyyy-MM-dd').log"
            $detections | ForEach-Object {
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$($_.ProcessName -or 'Task')|$($_.Risk)|$($_.CommandLine -or $_.Arguments)" | Add-Content -Path $logPath -ErrorAction SilentlyContinue
            }
            Write-Output "DETECTION:$ModuleName`:Found $($detections.Count) script host abuses"
        } else {
            Write-Output "STATS:$ModuleName`:OK"
        }
        return $detections.Count
    } catch {
        Write-Output "ERROR:$ModuleName`:$_"
        return 0
    }
}

function Start-Module {
    param([hashtable]$Config)
    while ($true) {
        try {
            $now = Get-Date
            if (($now - $LastTick).TotalSeconds -ge $TickInterval) {
                Invoke-ScriptHostDetection | Out-Null
                $LastTick = $now
            }
            Start-Sleep -Seconds 5
        } catch {
            Write-Output "ERROR:$ModuleName`:$_"
            Start-Sleep -Seconds 10
        }
    }
}

if (-not $ModuleConfig) { Start-Module -Config @{} }

