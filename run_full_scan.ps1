param(
  [string]$OutDir = ".\reports",
  [string]$RunLabel = "",
  [string]$IocPath = ".\ioc-example.json",
  [string]$BaselineIn = ".\baseline\exec-baseline.json",
  [string]$BaselineOut = "",
  [string]$TiFeedUrl = "",
  [string]$TiFeedToken = "",
  [string]$MispUrl = "",
  [string]$MispKey = "",
  [string]$VtApiKey = "",
  [switch]$VtUploadMalicious,
  [string]$SplunkHecUrl = "",
  [string]$SplunkHecToken = "",
  [string]$ElkUrl = "",
  [string]$ElkApiKey = "",
  [string]$SentinelWorkspaceId = "",
  [string]$SentinelSharedKey = "",
  [switch]$NoPauseAtEnd
)

$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot
$script:LogFile = $null

function Write-Log {
  param(
    [string]$Message,
    [string]$Level = "INFO",
    [ConsoleColor]$Color = [ConsoleColor]::Gray
  )
  $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
  $line = "[$ts] [$Level] $Message"
  Write-Host $line -ForegroundColor $Color
  if ($script:LogFile) {
    Add-Content -Path $script:LogFile -Value $line -Encoding UTF8
  }
}

function Step-Progress {
  param(
    [int]$Percent,
    [string]$Status
  )
  Write-Progress -Activity "secscan full run" -Status $Status -PercentComplete $Percent
  Write-Log -Message $Status -Level "STEP" -Color Cyan
}

function Invoke-TrackedProcess {
  param(
    [string]$FilePath,
    [string[]]$ArgumentList,
    [string]$Status,
    [int]$Percent,
    [int]$PollSeconds = 3
  )

  $stdoutFile = Join-Path $env:TEMP ("secscan-" + [guid]::NewGuid().ToString() + ".out.log")
  $stderrFile = Join-Path $env:TEMP ("secscan-" + [guid]::NewGuid().ToString() + ".err.log")
  $proc = Start-Process -FilePath $FilePath -ArgumentList $ArgumentList -RedirectStandardOutput $stdoutFile -RedirectStandardError $stderrFile -PassThru -WindowStyle Hidden
  $lastStdoutLines = 0
  $lastStderrLines = 0
  $start = Get-Date

  while (-not $proc.HasExited) {
    $elapsed = (Get-Date) - $start
    Write-Progress -Activity "secscan full run" -Status "$Status - running for $($elapsed.ToString('mm\:ss'))" -PercentComplete $Percent
    Write-Log -Message ("{0} - running for {1:mm\:ss}" -f $Status, $elapsed) -Level "HEARTBEAT" -Color DarkCyan

    if (Test-Path $stdoutFile) {
      $lines = Get-Content $stdoutFile
      if ($lines.Count -gt $lastStdoutLines) {
        $lines[$lastStdoutLines..($lines.Count - 1)] | ForEach-Object { if ($_ -ne "") { Write-Log -Message $_ -Level "STDOUT" -Color Gray } }
        $lastStdoutLines = $lines.Count
      }
    }
    if (Test-Path $stderrFile) {
      $lines = Get-Content $stderrFile
      if ($lines.Count -gt $lastStderrLines) {
        $lines[$lastStderrLines..($lines.Count - 1)] | ForEach-Object { if ($_ -ne "") { Write-Log -Message $_ -Level "STDERR" -Color Yellow } }
        $lastStderrLines = $lines.Count
      }
    }
    Start-Sleep -Seconds $PollSeconds
  }

  if (Test-Path $stdoutFile) {
    $lines = Get-Content $stdoutFile
    if ($lines.Count -gt $lastStdoutLines) {
      $lines[$lastStdoutLines..($lines.Count - 1)] | ForEach-Object { if ($_ -ne "") { Write-Log -Message $_ -Level "STDOUT" -Color Gray } }
    }
  }
  if (Test-Path $stderrFile) {
    $lines = Get-Content $stderrFile
    if ($lines.Count -gt $lastStderrLines) {
      $lines[$lastStderrLines..($lines.Count - 1)] | ForEach-Object { if ($_ -ne "") { Write-Log -Message $_ -Level "STDERR" -Color Yellow } }
    }
  }

  $exitCode = $proc.ExitCode
  Write-Log -Message ("{0} finished with exit_code={1}" -f $Status, $exitCode) -Level "PROC" -Color DarkGray
  Remove-Item $stdoutFile, $stderrFile -ErrorAction SilentlyContinue
  return $exitCode
}

$python = ".\.venv\Scripts\python.exe"
if (-not (Test-Path $python)) {
  Write-Host "[-] .venv not found. Run setup first:" -ForegroundColor Red
  Write-Host "    python -m venv .venv; .\.venv\Scripts\Activate.ps1; pip install -r requirements.txt" -ForegroundColor Yellow
  exit 1
}

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
if (-not $RunLabel) { $RunLabel = $timestamp }
$runDir = Join-Path $OutDir $RunLabel
New-Item -ItemType Directory -Force -Path $runDir | Out-Null
$script:LogFile = Join-Path $runDir "run.log"
Write-Log -Message "secscan full run started" -Level "START" -Color Green
Write-Log -Message ("RunDir: {0}" -f (Resolve-Path $runDir)) -Level "START" -Color Green

$reportPath = Join-Path $runDir "secscan-report.json"
$jsonlPath = Join-Path $runDir "secscan-findings.jsonl"
$summaryPath = Join-Path $runDir "secscan-summary.json"

$args = @(
  "-m", "secscan", "report",
  "--out", $reportPath,
  "--jsonl-out", $jsonlPath
)

if (Test-Path $IocPath) { $args += @("--ioc", $IocPath) }
if ($BaselineIn -and (Test-Path $BaselineIn)) { $args += @("--baseline-in", $BaselineIn) }
if ($BaselineOut) { $args += @("--baseline-out", $BaselineOut) }
if ($TiFeedUrl) { $args += @("--ti-feed-url", $TiFeedUrl) }
if ($TiFeedToken) { $args += @("--ti-feed-token", $TiFeedToken) }
if ($MispUrl) { $args += @("--misp-url", $MispUrl) }
if ($MispKey) { $args += @("--misp-key", $MispKey) }
if ($VtApiKey) { $args += @("--vt-api-key", $VtApiKey) }
if ($VtUploadMalicious.IsPresent) { $args += "--vt-upload-malicious" }
if ($SplunkHecUrl) { $args += @("--splunk-hec-url", $SplunkHecUrl) }
if ($SplunkHecToken) { $args += @("--splunk-hec-token", $SplunkHecToken) }
if ($ElkUrl) { $args += @("--elk-url", $ElkUrl) }
if ($ElkApiKey) { $args += @("--elk-api-key", $ElkApiKey) }
if ($SentinelWorkspaceId) { $args += @("--sentinel-workspace-id", $SentinelWorkspaceId) }
if ($SentinelSharedKey) { $args += @("--sentinel-shared-key", $SentinelSharedKey) }

Write-Log -Message "Execution plan:" -Level "PLAN" -Color DarkGray
Write-Log -Message ("- report out: {0}" -f $reportPath) -Level "PLAN" -Color DarkGray
Write-Log -Message ("- jsonl out : {0}" -f $jsonlPath) -Level "PLAN" -Color DarkGray
Write-Log -Message ("- summary   : {0}" -f $summaryPath) -Level "PLAN" -Color DarkGray
Write-Log -Message ("Command: {0} {1}" -f $python, ($args -join " ")) -Level "PLAN" -Color DarkGray

Step-Progress -Percent 10 -Status "Preparing scan arguments"
$scanStart = Get-Date
Step-Progress -Percent 35 -Status "Running secscan report (this is usually the longest step)"
$scanExit = Invoke-TrackedProcess -FilePath $python -ArgumentList $args -Status "Running secscan report" -Percent 35
if ($scanExit -ne 0) { exit $scanExit }
$scanElapsed = (Get-Date) - $scanStart
Write-Log -Message ("Report step done in {0:mm\:ss}" -f $scanElapsed) -Level "DONE" -Color Green

Step-Progress -Percent 75 -Status "Running aggregate analyzer"
$aggStart = Get-Date
$aggArgs = @(".\analyze_scan_results.py", "--reports-dir", $runDir, "--out", $summaryPath)
$aggExit = Invoke-TrackedProcess -FilePath $python -ArgumentList $aggArgs -Status "Running aggregate analyzer" -Percent 75
if ($aggExit -ne 0) { exit $aggExit }
$aggElapsed = (Get-Date) - $aggStart
Write-Log -Message ("Aggregate step done in {0:mm\:ss}" -f $aggElapsed) -Level "DONE" -Color Green

Step-Progress -Percent 100 -Status "Completed"
Write-Progress -Activity "secscan full run" -Completed
Write-Log -Message "Done." -Level "DONE" -Color Green
Write-Log -Message ("RunDir : {0}" -f $runDir) -Level "DONE" -Color Green
Write-Log -Message ("Report : {0}" -f $reportPath) -Level "DONE" -Color Green
Write-Log -Message ("JSONL  : {0}" -f $jsonlPath) -Level "DONE" -Color Green
Write-Log -Message ("Summary: {0}" -f $summaryPath) -Level "DONE" -Color Green
Write-Log -Message ("Run log: {0}" -f $script:LogFile) -Level "DONE" -Color Green

Write-Log -Message "Next action: run hidden ports kill workflow if needed:" -Level "NEXT" -Color Cyan
Write-Log -Message (".\.venv\Scripts\python -m secscan ports --kill-suspicious") -Level "NEXT" -Color Cyan

if (-not $NoPauseAtEnd.IsPresent) {
  Write-Host ""
  Read-Host "Press Enter to close"
}
