param(
  [Parameter(Mandatory = $true)][string]$ArtifactDirectory,
  [Parameter(Mandatory = $true)][string]$WorkDirectory
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

if ($null -eq ("QualificationNativeMethods" -as [type])) {
  Add-Type -TypeDefinition @"
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.ComTypes;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Win32.SafeHandles;

public static class QualificationNativeMethods {
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
    public static extern uint GetSystemWindowsDirectoryW(StringBuilder buffer, uint size);

    [DllImport("kernel32.dll", ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool GetFileInformationByHandle(
        SafeFileHandle file,
        out QualificationByHandleFileInformation information);
}

[StructLayout(LayoutKind.Sequential)]
public struct QualificationByHandleFileInformation {
    public uint FileAttributes;
    public FILETIME CreationTime;
    public FILETIME LastAccessTime;
    public FILETIME LastWriteTime;
    public uint VolumeSerialNumber;
    public uint FileSizeHigh;
    public uint FileSizeLow;
    public uint NumberOfLinks;
    public uint FileIndexHigh;
    public uint FileIndexLow;
}

public sealed class QualificationBoundedMemoryStream : MemoryStream {
    private readonly long limit;

    public QualificationBoundedMemoryStream(long limit) {
        if (limit < 1) throw new ArgumentOutOfRangeException(nameof(limit));
        this.limit = limit;
    }

    private void RequireCapacity(int count) {
        if (count < 0 || Length > limit - count) {
            throw new InvalidDataException("qualification native output exceeded its bound");
        }
    }

    public override void Write(byte[] buffer, int offset, int count) {
        RequireCapacity(count);
        base.Write(buffer, offset, count);
    }

    public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) {
        RequireCapacity(count);
        return base.WriteAsync(buffer, offset, count, cancellationToken);
    }

    public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default) {
        RequireCapacity(buffer.Length);
        return base.WriteAsync(buffer, cancellationToken);
    }
}
"@
}

function Get-OsWindowsDirectory {
  $capacity = 32768
  $buffer = [Text.StringBuilder]::new($capacity)
  $length = [QualificationNativeMethods]::GetSystemWindowsDirectoryW($buffer, [uint32]$capacity)
  if ($length -eq 0 -or $length -ge $capacity) {
    throw "Windows qualification could not obtain a bounded OS-trusted Windows directory."
  }
  $value = $buffer.ToString()
  if ($value.Length -ne $length -or $value.IndexOf([char]0) -ge 0 -or -not [IO.Path]::IsPathFullyQualified($value)) {
    throw "Windows qualification received an invalid OS-trusted Windows directory."
  }
  return [IO.Path]::GetFullPath($value)
}

function Get-ManagedFileIdentity([string]$Path) {
  $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
  try {
    $information = [QualificationByHandleFileInformation]::new()
    if (-not [QualificationNativeMethods]::GetFileInformationByHandle($stream.SafeFileHandle, [ref]$information)) {
      throw "Windows qualification could not inspect the exact managed SSH identity handle."
    }
    return [ordered]@{
      attributes = [uint32]$information.FileAttributes
      volume = [uint32]$information.VolumeSerialNumber
      index = (([uint64]$information.FileIndexHigh -shl 32) -bor [uint64]$information.FileIndexLow)
      links = [uint32]$information.NumberOfLinks
      size = (([uint64]$information.FileSizeHigh -shl 32) -bor [uint64]$information.FileSizeLow)
    }
  } finally {
    $stream.Dispose()
  }
}

function Test-ExactEntryExists([string]$Path) {
  $parent = [IO.Path]::GetDirectoryName($Path)
  $name = [IO.Path]::GetFileName($Path)
  if (-not (Test-Path -LiteralPath $parent -PathType Container)) {
    return $false
  }
  return @(
    Get-ChildItem -LiteralPath $parent -Force |
      Where-Object { [String]::Equals($_.Name, $name, [StringComparison]::OrdinalIgnoreCase) }
  ).Count -ne 0
}

function Assert-ManagedSshIdentityFile(
  [string]$Path,
  [uint64]$MaximumBytes,
  [string]$Label
) {
  $before = Get-ManagedFileIdentity $Path
  if (($before.attributes -band [uint32][IO.FileAttributes]::ReparsePoint) -ne 0 -or
      $before.links -ne 1 -or $before.size -eq 0 -or $before.size -gt $MaximumBytes) {
    throw "$Label is not an exact bounded single-link regular file."
  }
  $acl = Get-Acl -LiteralPath $Path
  $currentSid = [Security.Principal.WindowsIdentity]::GetCurrent().User
  $ownerSid = $acl.GetOwner([Security.Principal.SecurityIdentifier])
  $rules = @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))
  if (-not $acl.AreAccessRulesProtected -or -not $ownerSid.Equals($currentSid) -or $rules.Count -ne 1) {
    throw "$Label does not have an exact protected current-user-only DACL."
  }
  $rule = $rules[0]
  if ($rule.IsInherited -or -not $rule.IdentityReference.Equals($currentSid) -or
      $rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or
      $rule.FileSystemRights -ne [Security.AccessControl.FileSystemRights]::FullControl -or
      $rule.InheritanceFlags -ne [Security.AccessControl.InheritanceFlags]::None -or
      $rule.PropagationFlags -ne [Security.AccessControl.PropagationFlags]::None) {
    throw "$Label DACL grants anything other than exact current-user full control."
  }
  $encoding = [Text.UTF8Encoding]::new($false, $true)
  $text = [IO.File]::ReadAllText($Path, $encoding)
  $after = Get-ManagedFileIdentity $Path
  if ($before.volume -ne $after.volume -or $before.index -ne $after.index -or
      $before.links -ne $after.links -or $before.size -ne $after.size -or
      $before.attributes -ne $after.attributes) {
    throw "$Label changed while qualification inspected it."
  }
  return $text
}

function Assert-ManagedPrivateDirectory([string]$Path, [string]$Label) {
  $item = Get-Item -LiteralPath $Path -Force
  if (-not $item.PSIsContainer -or
      ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw "$Label is not an exact real directory."
  }
  $acl = Get-Acl -LiteralPath $Path
  $currentSid = [Security.Principal.WindowsIdentity]::GetCurrent().User
  $ownerSid = $acl.GetOwner([Security.Principal.SecurityIdentifier])
  $rules = @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))
  if (-not $acl.AreAccessRulesProtected -or -not $ownerSid.Equals($currentSid) -or $rules.Count -ne 1) {
    throw "$Label does not have an exact protected current-user-only DACL."
  }
  $rule = $rules[0]
  [Security.AccessControl.InheritanceFlags]$expectedInheritance = (
    [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
    [Security.AccessControl.InheritanceFlags]::ObjectInherit
  )
  if ($rule.IsInherited -or -not $rule.IdentityReference.Equals($currentSid) -or
      $rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or
      $rule.FileSystemRights -ne [Security.AccessControl.FileSystemRights]::FullControl -or
      $rule.InheritanceFlags -ne $expectedInheritance -or
      $rule.PropagationFlags -ne [Security.AccessControl.PropagationFlags]::None) {
    throw "$Label DACL grants anything other than inheritable current-user full control."
  }
}

function Assert-ManagedSshIdentity([string]$ProviderReleaseHome) {
  $identityDirectory = Join-Path $ProviderReleaseHome "data\containers\podman\machine"
  $privateKey = Join-Path $identityDirectory "machine"
  $publicKey = Join-Path $identityDirectory "machine.pub"
  $privateText = Assert-ManagedSshIdentityFile $privateKey (16 * 1024) "Managed SSH private key"
  $publicText = Assert-ManagedSshIdentityFile $publicKey (4 * 1024) "Managed SSH public key"
  if (-not $privateText.StartsWith("-----BEGIN OPENSSH PRIVATE KEY-----`n", [StringComparison]::Ordinal) -or
      -not $privateText.TrimEnd().EndsWith("-----END OPENSSH PRIVATE KEY-----", [StringComparison]::Ordinal)) {
    throw "Managed SSH private key is not an OpenSSH private key."
  }
  if ($publicText -cnotmatch "\Assh-ed25519 [A-Za-z0-9+/]+={0,2} ai-security-scanner-managed-runtime`n?\z") {
    throw "Managed SSH public key does not have the exact Ed25519 identity format."
  }
  foreach ($stagingName in @(".machine.private-key-new", ".machine.public-key-new")) {
    if (Test-ExactEntryExists (Join-Path $identityDirectory $stagingName)) {
      throw "Managed SSH identity staging entries remain after start."
    }
  }
}

function ConvertFrom-StrictWslInventory([byte[]]$Bytes) {
  if ($Bytes.Length -gt 1024 * 1024) {
    throw "Windows qualification WSL inventory exceeded its byte bound."
  }
  $strictUtf8 = [Text.UTF8Encoding]::new($false, $true)
  $strictUtf16Le = [Text.UnicodeEncoding]::new($false, $false, $true)
  [string]$decoded = ""
  if ($Bytes.Length -ge 3 -and $Bytes[0] -eq 0xef -and $Bytes[1] -eq 0xbb -and $Bytes[2] -eq 0xbf) {
    [byte[]]$payload = [byte[]]::new($Bytes.Length - 3)
    if ($payload.Length -ne 0) { [Array]::Copy($Bytes, 3, $payload, 0, $payload.Length) }
    try { $decoded = $strictUtf8.GetString($payload) }
    catch { throw "Windows qualification WSL inventory was not valid UTF-8." }
  } elseif ($Bytes.Length -ge 2 -and $Bytes[0] -eq 0xff -and $Bytes[1] -eq 0xfe) {
    [byte[]]$payload = [byte[]]::new($Bytes.Length - 2)
    if ($payload.Length -ne 0) { [Array]::Copy($Bytes, 2, $payload, 0, $payload.Length) }
    try { $decoded = $strictUtf16Le.GetString($payload) }
    catch { throw "Windows qualification WSL inventory was not valid UTF-16LE." }
  } elseif ($Bytes.Length -ge 2 -and $Bytes[0] -eq 0xfe -and $Bytes[1] -eq 0xff) {
    throw "Windows qualification WSL inventory used unsupported UTF-16BE."
  } else {
    $validUtf8 = $true
    try { $decoded = $strictUtf8.GetString($Bytes) }
    catch { $validUtf8 = $false }
    if (-not $validUtf8 -or $decoded.IndexOf([char]0) -ge 0) {
      try { $decoded = $strictUtf16Le.GetString($Bytes) }
      catch { throw "Windows qualification WSL inventory was neither valid UTF-8 nor UTF-16LE." }
    }
  }
  if ($decoded.IndexOf([char]0) -ge 0 -or $decoded.IndexOf([char]0xfeff) -ge 0) {
    throw "Windows qualification WSL inventory contained an invalid code point."
  }
  [string[]]$lines = $decoded.Split([char[]]@([char]10), [StringSplitOptions]::None)
  $distributions = [Collections.Generic.List[string]]::new()
  for ($lineIndex = 0; $lineIndex -lt $lines.Length; $lineIndex++) {
    $line = $lines[$lineIndex]
    if ($line.Length -eq 0 -and $lineIndex -eq $lines.Length - 1) {
      continue
    }
    if ($line.EndsWith("`r", [StringComparison]::Ordinal)) {
      $line = $line.Substring(0, $line.Length - 1)
    }
    if ($line.Length -eq 0 -or $strictUtf8.GetByteCount($line) -gt 256 -or $line.Trim() -cne $line) {
      throw "Windows qualification WSL inventory contained an invalid name."
    }
    for ($offset = 0; $offset -lt $line.Length; $offset++) {
      $codePoint = [char]::ConvertToUtf32($line, $offset)
      if ($codePoint -gt 0xffff) { $offset++ }
      if (($codePoint -ge 0 -and $codePoint -le 0x1f) -or
          ($codePoint -ge 0x7f -and $codePoint -le 0x9f) -or
          $codePoint -eq 0x2028 -or $codePoint -eq 0x2029 -or
          ($codePoint -ge 0xfdd0 -and $codePoint -le 0xfdef) -or
          ($codePoint -band 0xffff) -eq 0xfffe -or ($codePoint -band 0xffff) -eq 0xffff) {
        throw "Windows qualification WSL inventory contained an invalid name."
      }
    }
    if ($distributions.Count -eq 1024) {
      throw "Windows qualification WSL inventory contained too many names."
    }
    $distributions.Add($line)
  }
  return $distributions.ToArray()
}

function Invoke-WslInventoryRaw(
  [string]$Wsl,
  [string]$SystemRoot,
  [string]$System32,
  [string]$WorkingDirectory
) {
  $startInfo = [Diagnostics.ProcessStartInfo]::new()
  $startInfo.FileName = $Wsl
  $startInfo.UseShellExecute = $false
  $startInfo.CreateNoWindow = $true
  $startInfo.RedirectStandardOutput = $true
  $startInfo.RedirectStandardError = $true
  $startInfo.WorkingDirectory = $WorkingDirectory
  $startInfo.ArgumentList.Add("--list")
  $startInfo.ArgumentList.Add("--quiet")
  $startInfo.Environment.Clear()
  $startInfo.Environment["SystemRoot"] = $SystemRoot
  $startInfo.Environment["WINDIR"] = $SystemRoot
  $startInfo.Environment["PATH"] = $System32
  $startInfo.Environment["NoDefaultCurrentDirectoryInExePath"] = "1"
  $process = [Diagnostics.Process]::new()
  $process.StartInfo = $startInfo
  $stdout = [QualificationBoundedMemoryStream]::new(1024 * 1024)
  $stderr = [QualificationBoundedMemoryStream]::new(1024 * 1024)
  try {
    if (-not $process.Start()) {
      throw "Windows qualification could not start the OS-trusted WSL inventory executable."
    }
    $stdoutTask = $process.StandardOutput.BaseStream.CopyToAsync($stdout)
    $stderrTask = $process.StandardError.BaseStream.CopyToAsync($stderr)
    if (-not $process.WaitForExit(30000)) {
      try { $process.Kill($true) } catch {}
      $process.WaitForExit(5000) | Out-Null
      throw "Windows qualification WSL inventory exceeded its deadline."
    }
    $drain = [Threading.Tasks.Task]::WhenAll([Threading.Tasks.Task[]]@($stdoutTask, $stderrTask))
    try { $drained = $drain.Wait(5000) } catch { throw "Windows qualification WSL inventory output exceeded its bound or failed to drain." }
    if (-not $drained -or -not $drain.IsCompletedSuccessfully) {
      throw "Windows qualification WSL inventory output failed to drain within its deadline."
    }
    if ($process.ExitCode -ne 0) {
      throw "Windows qualification could not inventory WSL distributions after managed runtime uninstall."
    }
    return ConvertFrom-StrictWslInventory ($stdout.ToArray())
  } finally {
    $stdout.Dispose()
    $stderr.Dispose()
    $process.Dispose()
  }
}

$artifactRoot = (Resolve-Path -LiteralPath $ArtifactDirectory).Path
$runnerTemp = [IO.Path]::GetFullPath($env:RUNNER_TEMP)
$workRoot = [IO.Path]::GetFullPath($WorkDirectory)
if (-not $workRoot.StartsWith($runnerTemp + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
  throw "Qualification work directory must be below RUNNER_TEMP."
}
New-Item -ItemType Directory -Path $workRoot -Force | Out-Null
$installDirectory = Join-Path $runnerTemp "ai-security-scanner-platform-qualification-installed"
$reportedLocalApplicationData = [Environment]::GetFolderPath([Environment+SpecialFolder]::LocalApplicationData)
if ([String]::IsNullOrWhiteSpace($reportedLocalApplicationData) -or
    -not [IO.Path]::IsPathFullyQualified($reportedLocalApplicationData)) {
  throw "Windows qualification could not obtain OS-resolved LocalApplicationData."
}
$localApplicationData = [IO.Path]::GetFullPath($reportedLocalApplicationData)
$localApplicationDataItem = Get-Item -LiteralPath $localApplicationData -Force
if (-not $localApplicationDataItem.PSIsContainer -or
    ($localApplicationDataItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
  throw "OS-resolved LocalApplicationData is not a real directory."
}
$dataDirectory = [IO.Path]::GetFullPath(
  (Join-Path $localApplicationData "ai-security-scanner-platform-qualification-windows-data")
)
if (-not [String]::Equals(
    [IO.Path]::GetDirectoryName($dataDirectory),
    $localApplicationData,
    [StringComparison]::OrdinalIgnoreCase
  )) {
  throw "Qualification data directory escaped OS-resolved LocalApplicationData."
}
foreach ($boundedPath in @($installDirectory, $dataDirectory)) {
  if (-not ([IO.Path]::GetFileName($boundedPath)).StartsWith("ai-security-scanner-platform-qualification-", [StringComparison]::Ordinal)) {
    throw "Refusing an unexpected qualification cleanup path."
  }
}
if (Test-ExactEntryExists $dataDirectory) {
  throw "Qualification requires a fresh LocalApplicationData namespace."
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
  $runtimeContract = Get-Content -LiteralPath $runtimeManifest -Raw | ConvertFrom-Json
  $runtimeManifestSha256 = (Get-FileHash -LiteralPath $runtimeManifest -Algorithm SHA256).Hash.ToLowerInvariant()
  if ($runtimeManifestSha256 -cnotmatch "^[0-9a-f]{64}$") {
    throw "Windows qualification runtime manifest has an invalid SHA-256."
  }
  $providerReleaseHome = Join-Path $dataDirectory "managed-runtime\provider-home\$($runtimeManifestSha256.Substring(0, 16))"
  $windowsTargets = @(
    $runtimeContract.targets |
      Where-Object { $_.operating_system -eq "windows" -and $_.architecture -eq "x86_64" -and $_.provider -eq "wsl" }
  )
  if ($windowsTargets.Count -ne 1) {
    throw "Windows qualification requires exactly one Windows x86_64 WSL target."
  }
  $machineImageSha256 = [string]$windowsTargets[0].machine_image.sha256
  if ($machineImageSha256 -cnotmatch "^[0-9a-f]{64}$") {
    throw "Windows qualification target has an invalid machine-image SHA-256."
  }
  $managedMachineName = "assm1-win-x64-$($machineImageSha256.Substring(0, 12))"
  $managedWslDistribution = "podman-$managedMachineName"
  $reportedSystemRoot = Get-OsWindowsDirectory
  $systemRoot = (Resolve-Path -LiteralPath $reportedSystemRoot).Path
  $system32 = (Resolve-Path -LiteralPath (Join-Path $systemRoot "System32")).Path
  if (-not $system32.StartsWith($systemRoot + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
    throw "Windows qualification System32 escaped the OS-trusted Windows directory."
  }
  $wslItem = Get-Item -LiteralPath (Join-Path $system32 "wsl.exe") -Force
  $wsl = $wslItem.FullName
  if (-not [IO.Path]::IsPathFullyQualified($wsl) -or
      -not [String]::Equals([IO.Path]::GetDirectoryName($wsl), $system32, [StringComparison]::OrdinalIgnoreCase) -or
      $wslItem.PSIsContainer -or ($wslItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw "Windows qualification requires the real absolute OS-trusted System32 wsl.exe."
  }

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
  $podmanNamespaceDirectories = @(
    (Join-Path $providerReleaseHome "run\podman"),
    (Join-Path $providerReleaseHome "config\containers\podman\machine\wsl"),
    (Join-Path $providerReleaseHome "data\containers\podman\machine"),
    (Join-Path $providerReleaseHome "data\containers\podman\machine\wsl\cache")
  )
  foreach ($namespaceDirectory in $podmanNamespaceDirectories) {
    Assert-ManagedPrivateDirectory $namespaceDirectory "Managed Podman namespace directory"
  }
  $startStatus = Invoke-Managed "start" @("start")
  Assert-ManagedSshIdentity $providerReleaseHome
  $runningStatus = Invoke-Managed "running-status" @("status")
  $containerQualification = Invoke-Managed "container-qualification" @("qualify")
  $stopStatus = Invoke-Managed "stop" @("stop")
  $stoppedStatus = Invoke-Managed "stopped-status" @("status")
  $uninstallStatus = Invoke-Managed "uninstall-purge" @("uninstall", "--force", "--purge-image-cache")
  if (Test-ExactEntryExists $providerReleaseHome) {
    throw "Managed runtime uninstall left its exact release provider home behind."
  }
  $remainingWslDistributions = @(Invoke-WslInventoryRaw $wsl $systemRoot $system32 $workRoot)
  foreach ($distribution in $remainingWslDistributions) {
    if ([String]::Equals([string]$distribution, $managedWslDistribution, [StringComparison]::OrdinalIgnoreCase)) {
      throw "Managed runtime uninstall left its exact WSL distribution registered: $managedWslDistribution"
    }
  }
  $finalStatus = Invoke-Managed "final-status" @("status")

  foreach ($privateRoot in @(
    (Join-Path $dataDirectory "managed-runtime\versions"),
    (Join-Path $dataDirectory "managed-runtime\machine-images"),
    (Join-Path $dataDirectory "managed-runtime\provider-home")
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
