param(
  [Parameter(Mandatory = $true)][string]$ArtifactDirectory,
  [Parameter(Mandatory = $true)][string]$WorkDirectory
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$artifactRoot = (Resolve-Path -LiteralPath $ArtifactDirectory).Path
$runnerTemp = [IO.Path]::GetFullPath($env:RUNNER_TEMP)
$workRoot = [IO.Path]::GetFullPath($WorkDirectory)
if (-not $workRoot.StartsWith($runnerTemp + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
  throw "Qualification work directory must be below RUNNER_TEMP."
}
New-Item -ItemType Directory -Path $workRoot -Force | Out-Null
$installDirectory = Join-Path $runnerTemp "ai-security-scanner-platform-qualification-installed"
$dataDirectory = Join-Path $runnerTemp "ai-security-scanner-platform-qualification-windows-data"
foreach ($boundedPath in @($installDirectory, $dataDirectory)) {
  if (-not ([IO.Path]::GetFileName($boundedPath)).StartsWith("ai-security-scanner-platform-qualification-", [StringComparison]::Ordinal)) {
    throw "Refusing an unexpected qualification cleanup path."
  }
}

$installed = $false
$installerPath = $null
try {
  $installerManifestPath = Join-Path $artifactRoot "installers-windows-x86_64.json"
  $installerManifest = Get-Content -LiteralPath $installerManifestPath -Raw | ConvertFrom-Json
  $installers = @($installerManifest.installers | Where-Object { $_.bundleType -eq "msi" })
  if ($installers.Count -ne 1 -or [IO.Path]::GetFileName($installers[0].file) -ne $installers[0].file) {
    throw "Windows qualification requires exactly one flat MSI installer."
  }
  $installerPath = (Resolve-Path -LiteralPath (Join-Path $artifactRoot $installers[0].file)).Path
  if ([IO.Path]::GetDirectoryName($installerPath) -ne $artifactRoot) {
    throw "MSI installer escaped the downloaded release artifact directory."
  }

  $install = Start-Process -FilePath "msiexec.exe" -ArgumentList @(
    "/i", $installerPath, "INSTALLDIR=$installDirectory", "/qn", "/norestart"
  ) -Wait -PassThru
  if ($install.ExitCode -ne 0) {
    throw "MSI installation failed with status $($install.ExitCode)."
  }
  $installed = $true

  function Find-OneInstalledFile([string]$Name, [scriptblock]$Filter = { $true }) {
    $matches = @(Get-ChildItem -LiteralPath $installDirectory -Filter $Name -File -Recurse | Where-Object $Filter)
    if ($matches.Count -ne 1) {
      throw "Expected exactly one installed $Name, found $($matches.Count)."
    }
    if (-not [IO.Path]::IsPathFullyQualified($matches[0].FullName)) {
      throw "Installed $Name path is not absolute."
    }
    return $matches[0].FullName
  }

  $desktop = Find-OneInstalledFile "ai-security-scanner.exe" { $_.FullName -notmatch "(?i)uninstall" }
  $egress = Find-OneInstalledFile "ai-security-scanner-egress-gateway.exe"
  $broker = Find-OneInstalledFile "ai-security-scanner-bootstrap-broker.exe"
  $cli = Find-OneInstalledFile "ai-security-scanner-cli.exe"
  $runtimeManifests = @(
    Get-ChildItem -LiteralPath $installDirectory -Filter "manifest.json" -File -Recurse |
      Where-Object { $_.FullName -match "(?i)[\\/]managed-runtime[\\/]manifest\.json$" }
  )
  if ($runtimeManifests.Count -ne 1) {
    throw "Expected exactly one installed managed-runtime manifest, found $($runtimeManifests.Count)."
  }
  $runtimeManifest = $runtimeManifests[0].FullName
  Copy-Item -LiteralPath $runtimeManifest -Destination (Join-Path $workRoot "installed-runtime-manifest.json")

  & $cli --help | Out-Null
  if ($LASTEXITCODE -ne 0) {
    throw "Installed casework CLI failed its help probe."
  }
  $desktopProcess = Start-Process -FilePath $desktop -PassThru
  Start-Sleep -Seconds 12
  if ($desktopProcess.HasExited) {
    throw "Installed Windows desktop exited before the 12-second observation window with status $($desktopProcess.ExitCode)."
  }
  Stop-Process -Id $desktopProcess.Id -Force
  $desktopProcess.WaitForExit()

  New-Item -ItemType Directory -Path $dataDirectory -Force | Out-Null
  function Invoke-Managed([string]$OutputName, [string[]]$Arguments) {
    $stdout = Join-Path $workRoot "$OutputName.json"
    $stderr = Join-Path $workRoot "$OutputName.stderr.log"
    & $cli --json --data-dir $dataDirectory runtime managed @Arguments 1> $stdout 2> $stderr
    if ($LASTEXITCODE -ne 0) {
      $failure = Get-Content -LiteralPath $stderr -Raw -ErrorAction SilentlyContinue
      throw "Managed runtime command $OutputName failed: $failure"
    }
    try {
      return Get-Content -LiteralPath $stdout -Raw | ConvertFrom-Json
    } catch {
      throw "Managed runtime command $OutputName did not emit one JSON document."
    }
  }

  $initialStatus = Invoke-Managed "initial-status" @("status")
  $installStatus = Invoke-Managed "install" @("install")
  $installedStatus = Invoke-Managed "installed-status" @("status")
  $startStatus = Invoke-Managed "start" @("start")
  $runningStatus = Invoke-Managed "running-status" @("status")
  $containerQualification = Invoke-Managed "container-qualification" @("qualify")
  $stopStatus = Invoke-Managed "stop" @("stop")
  $stoppedStatus = Invoke-Managed "stopped-status" @("status")
  $uninstallStatus = Invoke-Managed "uninstall-purge" @("uninstall", "--force", "--purge-image-cache")
  $finalStatus = Invoke-Managed "final-status" @("status")

  foreach ($privateRoot in @(
    (Join-Path $dataDirectory "managed-runtime\versions"),
    (Join-Path $dataDirectory "managed-runtime\machine-images")
  )) {
    if ((Test-Path -LiteralPath $privateRoot) -and @(Get-ChildItem -LiteralPath $privateRoot -Force).Count -ne 0) {
      throw "Managed runtime cleanup left private entries below $privateRoot."
    }
  }

  $uninstall = Start-Process -FilePath "msiexec.exe" -ArgumentList @(
    "/x", $installerPath, "/qn", "/norestart"
  ) -Wait -PassThru
  if ($uninstall.ExitCode -ne 0) {
    throw "MSI uninstall failed with status $($uninstall.ExitCode)."
  }
  $installed = $false
  if (Test-Path -LiteralPath $installDirectory) {
    Remove-Item -LiteralPath $installDirectory -Recurse -Force
  }
  if (Test-Path -LiteralPath $installDirectory) {
    throw "MSI installation directory remains after cleanup."
  }
  Remove-Item -LiteralPath $dataDirectory -Recurse -Force
  if (Test-Path -LiteralPath $dataDirectory) {
    throw "Private qualification data remains after cleanup."
  }

  function Passed([string]$Name, [object]$Status) {
    return [ordered]@{ name = $Name; outcome = "passed"; status = $Status }
  }
  $observations = [ordered]@{
    installedLayout = [ordered]@{
      pathsVerifiedAbsolute = $true
      desktop = $desktop
      cli = $cli
      companions = @(
        [ordered]@{ name = "ai-security-scanner-egress-gateway"; path = $egress },
        [ordered]@{ name = "ai-security-scanner-bootstrap-broker"; path = $broker },
        [ordered]@{ name = "ai-security-scanner-cli"; path = $cli }
      )
      runtimeManifestOriginalPath = $runtimeManifest
    }
    desktopStartup = [ordered]@{ outcome = "passed"; observationSeconds = 12; installedExecutable = $desktop }
    privateDataDirectory = $dataDirectory
    operations = @(
      (Passed "initial_status" $initialStatus),
      (Passed "install" $installStatus),
      (Passed "installed_status" $installedStatus),
      (Passed "start" $startStatus),
      (Passed "running_status" $runningStatus),
      (Passed "stop" $stopStatus),
      (Passed "stopped_status" $stoppedStatus),
      (Passed "uninstall_purge" $uninstallStatus),
      (Passed "final_status" $finalStatus)
    )
    containerExecution = [ordered]@{ outcome = "passed"; result = $containerQualification }
    cleanup = [ordered]@{ managedRuntimePurged = $true; machineImageCachePurged = $true; installerRemoved = $true; privateDataRemoved = $true }
    installedManifestSnapshot = "installed-runtime-manifest.json"
  }
  $observations | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath (Join-Path $workRoot "observations.json") -Encoding utf8NoBOM -NoNewline
  Add-Content -LiteralPath (Join-Path $workRoot "observations.json") -Value "" -Encoding utf8NoBOM
} finally {
  if ($installed -and $null -ne $installerPath) {
    Start-Process -FilePath "msiexec.exe" -ArgumentList @("/x", $installerPath, "/qn", "/norestart") -Wait | Out-Null
  }
  foreach ($boundedPath in @($installDirectory, $dataDirectory)) {
    if (Test-Path -LiteralPath $boundedPath) {
      Remove-Item -LiteralPath $boundedPath -Recurse -Force
    }
  }
}
