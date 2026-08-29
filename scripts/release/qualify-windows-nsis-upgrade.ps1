param(
  [Parameter(Mandatory = $true)][string]$ArtifactDirectory,
  [Parameter(Mandatory = $true)][string]$WorkDirectory,
  [Parameter(Mandatory = $true)][string]$CurrentVersion
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$priorVersion = "0.1.7"
$priorTag = "v0.1.7"
$priorInstallerName = "ai-security-scanner_0.1.7_x64-setup.exe"
$priorInstallerBytes = 38730365
$priorInstallerSha256 = "4d2057ca4c008b46dc0195a792075e4b4b377c1909a7795b29efc30f9ae48b1a"
$priorInstallerUrl = "https://github.com/teddashh/ai-security-scanner/releases/download/v0.1.7/ai-security-scanner_0.1.7_x64-setup.exe"
$priorRuntimeManifestSha256 = "8b2257ace33ecb14bb0995044a4e6d2b4e71b314741601122801fbb59e7de13f"
$priorMachineImageSha256 = "e2b6cbcadd8b41b708fecb58a246a20d737dee0ef26872a3f75b575f77eba968"
$maximumPriorDownloadBytes = 64 * 1024 * 1024
$maximumRetainedCaseBundleBytes = 64 * 1024 * 1024
$maximumDataSnapshotBytes = 512 * 1024 * 1024
$maximumDataSnapshotFiles = 4096

if ($null -eq ("NsisUpgradeQualificationNativeMethods" -as [type])) {
  Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.ComTypes;
using Microsoft.Win32.SafeHandles;

public static class NsisUpgradeQualificationNativeMethods {
    public const uint GENERIC_READ = 0x80000000;
    public const uint FILE_SHARE_READ = 0x00000001;
    public const uint OPEN_EXISTING = 3;
    public const uint FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000;

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
    public static extern SafeFileHandle CreateFileW(
        string fileName,
        uint desiredAccess,
        uint shareMode,
        IntPtr securityAttributes,
        uint creationDisposition,
        uint flagsAndAttributes,
        IntPtr templateFile);

    [DllImport("kernel32.dll", ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool GetFileInformationByHandle(
        SafeFileHandle file,
        out NsisUpgradeQualificationByHandleFileInformation information);
}

[StructLayout(LayoutKind.Sequential)]
public struct NsisUpgradeQualificationByHandleFileInformation {
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
"@
}

function Assert-ExactChildPath([string]$Parent, [string]$Child, [string]$ExpectedName, [string]$Label) {
  $parentPath = [IO.Path]::GetFullPath($Parent)
  $childPath = [IO.Path]::GetFullPath($Child)
  if (-not [String]::Equals(
      [IO.Path]::GetDirectoryName($childPath),
      $parentPath,
      [StringComparison]::OrdinalIgnoreCase
    ) -or -not [String]::Equals(
      [IO.Path]::GetFileName($childPath),
      $ExpectedName,
      [StringComparison]::Ordinal
    )) {
    throw "$Label escaped its fixed parent or changed its fixed name."
  }
  return $childPath
}

function Get-OpenFileIdentity([IO.FileStream]$Stream) {
  $information = [NsisUpgradeQualificationByHandleFileInformation]::new()
  if (-not [NsisUpgradeQualificationNativeMethods]::GetFileInformationByHandle($Stream.SafeFileHandle, [ref]$information)) {
    throw "Could not inspect the exact qualification file handle."
  }
  return [ordered]@{
    attributes = [uint32]$information.FileAttributes
    links = [uint32]$information.NumberOfLinks
    bytes = (([uint64]$information.FileSizeHigh -shl 32) -bor [uint64]$information.FileSizeLow)
    volume = [uint32]$information.VolumeSerialNumber
    index = (([uint64]$information.FileIndexHigh -shl 32) -bor [uint64]$information.FileIndexLow)
  }
}

function Get-VerbatimWindowsPath([string]$Path, [string]$Label) {
  if ([String]::IsNullOrWhiteSpace($Path) -or -not [IO.Path]::IsPathFullyQualified($Path)) {
    throw "$Label is not an absolute Windows path."
  }
  $full = [IO.Path]::GetFullPath($Path)
  if ($full.StartsWith("\\?\", [StringComparison]::Ordinal)) { return $full }
  if ($full.StartsWith("\\", [StringComparison]::Ordinal)) {
    return "\\?\UNC\" + $full.Substring(2)
  }
  return "\\?\" + $full
}

function Open-NoFollowSingleLinkFile(
  [string]$Path,
  [string]$Label,
  [uint64]$MaximumBytes = [uint64]::MaxValue
) {
  $verbatimPath = Get-VerbatimWindowsPath $Path $Label
  $handle = [NsisUpgradeQualificationNativeMethods]::CreateFileW(
    $verbatimPath,
    [NsisUpgradeQualificationNativeMethods]::GENERIC_READ,
    [NsisUpgradeQualificationNativeMethods]::FILE_SHARE_READ,
    [IntPtr]::Zero,
    [NsisUpgradeQualificationNativeMethods]::OPEN_EXISTING,
    [NsisUpgradeQualificationNativeMethods]::FILE_FLAG_OPEN_REPARSE_POINT,
    [IntPtr]::Zero
  )
  if ($null -eq $handle -or $handle.IsInvalid) {
    $errorCode = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
    if ($null -ne $handle) { $handle.Dispose() }
    throw [ComponentModel.Win32Exception]::new($errorCode, "$Label could not be opened without following reparse points")
  }
  try {
    $stream = [IO.FileStream]::new($handle, [IO.FileAccess]::Read, 4096, $false)
  } catch {
    $handle.Dispose()
    throw
  }
  try {
    $identity = Get-OpenFileIdentity $stream
    if (($identity.attributes -band [uint32][IO.FileAttributes]::Directory) -ne 0 -or
        ($identity.attributes -band [uint32][IO.FileAttributes]::ReparsePoint) -ne 0 -or
        $identity.links -ne 1 -or $identity.bytes -lt 1 -or $identity.bytes -gt $MaximumBytes) {
      throw "$Label is not one bounded no-follow single-link regular file."
    }
    return ,$stream
  } catch {
    $stream.Dispose()
    throw
  }
}

function Assert-RealFile(
  [string]$Path,
  [string]$Label,
  [uint64]$MaximumBytes = [uint64]::MaxValue
) {
  $stream = Open-NoFollowSingleLinkFile $Path $Label $MaximumBytes
  try { $identity = Get-OpenFileIdentity $stream }
  finally { $stream.Dispose() }
  return [PSCustomObject]@{
    FullName = [IO.Path]::GetFullPath($Path)
    Length = [int64]$identity.bytes
  }
}

function Assert-OwnerOnlyFullControlFile(
  [string]$Path,
  [string]$Label,
  [uint64]$MaximumBytes = 64 * 1024
) {
  $stream = Open-NoFollowSingleLinkFile $Path $Label $MaximumBytes
  try {
    $before = Get-OpenFileIdentity $stream
    $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
    $currentSid = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $ownerSid = $acl.GetOwner([Security.Principal.SecurityIdentifier])
    $rules = @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))
    if ($null -eq $currentSid -or $ownerSid.Value -cne $currentSid.Value -or
        -not $acl.AreAccessRulesProtected -or -not $acl.AreAccessRulesCanonical -or
        $rules.Count -ne 1) {
      throw "$Label is not owned by exactly the current user with one protected canonical DACL."
    }
    $rule = $rules[0]
    if ($rule.IdentityReference.Value -cne $currentSid.Value -or
        $rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or
        $rule.IsInherited -or
        $rule.InheritanceFlags -ne [Security.AccessControl.InheritanceFlags]::None -or
        $rule.PropagationFlags -ne [Security.AccessControl.PropagationFlags]::None -or
        [uint32]$rule.FileSystemRights -ne [uint32][Security.AccessControl.FileSystemRights]::FullControl) {
      throw "$Label does not have the exact one-current-user FILE_ALL_ACCESS ACE."
    }
    $after = Get-OpenFileIdentity $stream
    if ($before.attributes -ne $after.attributes -or $before.links -ne $after.links -or
        $before.bytes -ne $after.bytes -or $before.volume -ne $after.volume -or
        $before.index -ne $after.index) {
      throw "$Label changed while its exact ownership and DACL were inspected."
    }
    return [PSCustomObject]@{
      FullName = [IO.Path]::GetFullPath($Path)
      Length = [int64]$before.bytes
    }
  } finally {
    $stream.Dispose()
  }
}

function Assert-RealDirectory([string]$Path, [string]$Label) {
  $item = Get-Item -LiteralPath $Path -Force
  if (-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw "$Label is not one real directory."
  }
  return $item
}

function Get-NoFollowFileSha256Proof(
  [string]$Path,
  [string]$Label,
  [uint64]$MaximumBytes = 8GB
) {
  $stream = Open-NoFollowSingleLinkFile $Path $Label $MaximumBytes
  try {
    $before = Get-OpenFileIdentity $stream
    $digest = [Security.Cryptography.SHA256]::HashData($stream)
    $after = Get-OpenFileIdentity $stream
    if ($before.attributes -ne $after.attributes -or $before.links -ne $after.links -or
        $before.bytes -ne $after.bytes -or $before.volume -ne $after.volume -or
        $before.index -ne $after.index) {
      throw "$Label changed while its exact no-follow handle was hashed."
    }
    return [PSCustomObject]@{
      FullName = [IO.Path]::GetFullPath($Path)
      Length = [int64]$before.bytes
      Sha256 = [Convert]::ToHexString($digest).ToLowerInvariant()
      Volume = [uint32]$before.volume
      FileIndex = [uint64]$before.index
    }
  } finally {
    $stream.Dispose()
  }
}

function Get-LowerSha256([string]$Path, [uint64]$MaximumBytes = 8GB) {
  return (Get-NoFollowFileSha256Proof $Path "SHA-256 input" $MaximumBytes).Sha256
}

function Read-BoundedUtf8File([string]$Path, [string]$Label, [uint64]$MaximumBytes = 64 * 1024) {
  $stream = Open-NoFollowSingleLinkFile $Path $Label $MaximumBytes
  try {
    $before = Get-OpenFileIdentity $stream
    [byte[]]$bytes = [byte[]]::new([int]$before.bytes)
    $offset = 0
    while ($offset -lt $bytes.Length) {
      $read = $stream.Read($bytes, $offset, $bytes.Length - $offset)
      if ($read -eq 0) { throw "$Label ended before its inspected byte length." }
      $offset += $read
    }
    $after = Get-OpenFileIdentity $stream
    if ($before.attributes -ne $after.attributes -or $before.links -ne $after.links -or
        $before.bytes -ne $after.bytes -or $before.volume -ne $after.volume -or
        $before.index -ne $after.index) {
      throw "$Label changed while its exact handle was read."
    }
    return [PSCustomObject]@{
      Text = [Text.UTF8Encoding]::new($false, $true).GetString($bytes)
      Length = [int64]$before.bytes
    }
  } catch {
    throw "$Label is not one stable bounded UTF-8 file: $($_.Exception.Message)"
  } finally {
    $stream.Dispose()
  }
}

function Read-BoundedJsonFile([string]$Path, [string]$Label, [uint64]$MaximumBytes = 64 * 1024) {
  $record = Read-BoundedUtf8File $Path $Label $MaximumBytes
  try {
    return $record.Text | ConvertFrom-Json -DateKind String
  } catch {
    throw "$Label is not one stable bounded UTF-8 JSON document: $($_.Exception.Message)"
  }
}

function Convert-JsonTextToCompactUtf8Bytes(
  [string]$Text,
  [string]$PropertyName = ""
) {
  $document = [Text.Json.JsonDocument]::Parse($Text)
  $memory = [IO.MemoryStream]::new()
  $writerOptions = [Text.Json.JsonWriterOptions]::new()
  # This output is hashed, not embedded in HTML. Rust serde_json leaves the
  # standard Base64 `+` byte literal, while the default .NET encoder rewrites
  # it as `\u002B` and would therefore compute a different digest.
  $writerOptions.Encoder = [Text.Encodings.Web.JavaScriptEncoder]::UnsafeRelaxedJsonEscaping
  $writer = [Text.Json.Utf8JsonWriter]::new($memory, $writerOptions)
  try {
    $element = if ([String]::IsNullOrEmpty($PropertyName)) {
      $document.RootElement
    } else {
      $document.RootElement.GetProperty($PropertyName)
    }
    $element.WriteTo($writer)
    $writer.Flush()
    [byte[]]$bytes = $memory.ToArray()
  } finally {
    $writer.Dispose()
    $memory.Dispose()
    $document.Dispose()
  }
  return ,$bytes
}

function Assert-SerdeCompatibleJsonCompaction {
  $fixture = '{"public_key_base64":"A\u002BB\/=="}'
  $expected = '{"public_key_base64":"A+B/=="}'
  [byte[]]$fixtureBytes = Convert-JsonTextToCompactUtf8Bytes $fixture
  $observed = [Text.Encoding]::UTF8.GetString($fixtureBytes)
  if ($observed -cne $expected) {
    throw "JSON compaction is not byte-compatible with the Rust signing-identity digest contract."
  }
}

Assert-SerdeCompatibleJsonCompaction

function Get-LowerSha256Bytes([byte[]]$Bytes) {
  return [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($Bytes)).ToLowerInvariant()
}

function Assert-ExactJsonProperties([object]$Value, [string[]]$ExpectedNames, [string]$Label) {
  $actual = @($Value.PSObject.Properties.Name | Sort-Object)
  $expected = @($ExpectedNames | Sort-Object)
  if (($actual -join "`n") -cne ($expected -join "`n")) {
    throw "$Label has unexpected or missing JSON properties."
  }
}

function Invoke-ExactProcess(
  [string]$FileName,
  [string[]]$Arguments,
  [int]$TimeoutMilliseconds,
  [string]$Label,
  [bool]$CaptureOutput = $false,
  [object]$ExpectedExecutableProof = $null
) {
  if ($TimeoutMilliseconds -lt 1000 -or $TimeoutMilliseconds -gt 900000) {
    throw "$Label timeout is outside its fixed bound."
  }
  $startInfo = [Diagnostics.ProcessStartInfo]::new()
  $startInfo.FileName = $FileName
  $startInfo.UseShellExecute = $false
  $startInfo.CreateNoWindow = $true
  $startInfo.RedirectStandardOutput = $CaptureOutput
  $startInfo.RedirectStandardError = $CaptureOutput
  foreach ($argument in $Arguments) {
    $startInfo.ArgumentList.Add($argument)
  }
  $process = [Diagnostics.Process]::new()
  $process.StartInfo = $startInfo
  try {
    $executionGuard = Open-NoFollowSingleLinkFile $FileName "$Label executable" (512 * 1024 * 1024)
    try {
      if ($null -ne $ExpectedExecutableProof) {
        foreach ($requiredProofField in @("FullName", "Length", "Sha256", "Volume", "FileIndex")) {
          if ($null -eq $ExpectedExecutableProof.PSObject.Properties[$requiredProofField]) {
            throw "$Label has an incomplete expected executable proof."
          }
        }
        if (-not [String]::Equals(
            [IO.Path]::GetFullPath($FileName),
            [string]$ExpectedExecutableProof.FullName,
            [StringComparison]::OrdinalIgnoreCase
          ) -or [int64]$ExpectedExecutableProof.Length -lt 1 -or
          [string]$ExpectedExecutableProof.Sha256 -cnotmatch '^[0-9a-f]{64}$') {
          throw "$Label has a malformed expected executable proof."
        }
        $beforeExecution = Get-OpenFileIdentity $executionGuard
        $executionGuard.Position = 0
        $executionDigest = [Security.Cryptography.SHA256]::HashData($executionGuard)
        $afterHash = Get-OpenFileIdentity $executionGuard
        if ($beforeExecution.attributes -ne $afterHash.attributes -or
            $beforeExecution.links -ne $afterHash.links -or
            $beforeExecution.bytes -ne $afterHash.bytes -or
            $beforeExecution.volume -ne $afterHash.volume -or
            $beforeExecution.index -ne $afterHash.index) {
          throw "$Label executable changed while its launch proof was hashed."
        }
        $executionSha256 = [Convert]::ToHexString($executionDigest).ToLowerInvariant()
        if ([uint64]$beforeExecution.bytes -ne [uint64]$ExpectedExecutableProof.Length -or
            [uint32]$beforeExecution.volume -ne [uint32]$ExpectedExecutableProof.Volume -or
            [uint64]$beforeExecution.index -ne [uint64]$ExpectedExecutableProof.FileIndex -or
            $executionSha256 -cne [string]$ExpectedExecutableProof.Sha256) {
          throw "$Label executable is not the exact previously verified installer."
        }
        $executionGuard.Position = 0
      }
      $started = $process.Start()
      if ($null -ne $ExpectedExecutableProof) {
        $afterStart = Get-OpenFileIdentity $executionGuard
        if ([uint64]$afterStart.bytes -ne [uint64]$ExpectedExecutableProof.Length -or
            [uint32]$afterStart.volume -ne [uint32]$ExpectedExecutableProof.Volume -or
            [uint64]$afterStart.index -ne [uint64]$ExpectedExecutableProof.FileIndex) {
          throw "$Label executable changed while the verified process was started."
        }
      }
    } finally {
      $executionGuard.Dispose()
    }
    if (-not $started) {
      throw "$Label did not start."
    }
    $stdoutTask = $null
    $stderrTask = $null
    if ($CaptureOutput) {
      $stdoutTask = $process.StandardOutput.ReadToEndAsync()
      $stderrTask = $process.StandardError.ReadToEndAsync()
    }
    if (-not $process.WaitForExit($TimeoutMilliseconds)) {
      try { $process.Kill($true) } catch {}
      $process.WaitForExit(5000) | Out-Null
      throw "$Label exceeded its fixed deadline."
    }
    $stdout = ""
    $stderr = ""
    if ($CaptureOutput) {
      if (-not [Threading.Tasks.Task]::WaitAll(@($stdoutTask, $stderrTask), 5000)) {
        throw "$Label output did not drain within its fixed deadline."
      }
      $stdout = $stdoutTask.Result
      $stderr = $stderrTask.Result
      if ([Text.Encoding]::UTF8.GetByteCount($stdout) -gt 1024 * 1024 -or
          [Text.Encoding]::UTF8.GetByteCount($stderr) -gt 1024 * 1024) {
        throw "$Label output exceeded one MiB."
      }
    }
    if ($process.ExitCode -ne 0) {
      $boundedError = if ($stderr.Length -gt 2048) { $stderr.Substring(0, 2048) + " (truncated)" } else { $stderr }
      throw "$Label failed with status $($process.ExitCode): $boundedError"
    }
    return [ordered]@{ stdout = $stdout; stderr = $stderr; exitCode = $process.ExitCode }
  } finally {
    $process.Dispose()
  }
}

function Invoke-CliJson([string]$Cli, [string[]]$Arguments, [string]$Label) {
  $result = Invoke-ExactProcess $Cli $Arguments 120000 $Label $true
  try {
    return $result.stdout | ConvertFrom-Json -DateKind String
  } catch {
    throw "$Label did not emit one valid JSON document."
  }
}

function Get-CliVersion([string]$Cli, [string]$Label) {
  $result = Invoke-ExactProcess $Cli @("--version") 30000 "$Label version probe" $true
  $value = $result.stdout.Trim()
  $match = [Text.RegularExpressions.Regex]::Match(
    $value,
    "^ai-security-scanner ([0-9]+\.[0-9]+\.[0-9]+)$",
    [Text.RegularExpressions.RegexOptions]::CultureInvariant
  )
  if (-not $match.Success) {
    throw "$Label returned an unexpected version string."
  }
  return $match.Groups[1].Value
}

function Find-OneInstalledFile([string]$InstallDirectory, [string]$Name) {
  $matches = @(
    Get-ChildItem -LiteralPath $InstallDirectory -Filter $Name -File -Recurse -Force |
      Where-Object { ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0 }
  )
  if ($matches.Count -ne 1) {
    throw "Expected exactly one installed $Name, found $($matches.Count)."
  }
  $fullPath = [IO.Path]::GetFullPath($matches[0].FullName)
  if (-not $fullPath.StartsWith(
      [IO.Path]::GetFullPath($InstallDirectory) + [IO.Path]::DirectorySeparatorChar,
      [StringComparison]::OrdinalIgnoreCase
    )) {
    throw "Installed $Name escaped the fixed installation directory."
  }
  Assert-RealFile $fullPath "Installed $Name" (512 * 1024 * 1024) | Out-Null
  return $fullPath
}

function Get-CurrentUserUninstallEntries {
  $root = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall"
  if (-not (Test-Path -LiteralPath $root -PathType Container)) {
    return @()
  }
  $children = @(Get-ChildItem -LiteralPath $root -ErrorAction Stop)
  if ($children.Count -gt 512) {
    throw "The current-user uninstall registry exceeded its qualification bound."
  }
  return @(
    $children |
      ForEach-Object {
        $properties = Get-ItemProperty -LiteralPath $_.PSPath -ErrorAction Stop
        $displayNameProperty = $properties.PSObject.Properties["DisplayName"]
        if ($null -ne $displayNameProperty -and
            [String]::Equals([string]$displayNameProperty.Value, "ai-security-scanner", [StringComparison]::Ordinal)) {
          $transitionProperty = $properties.PSObject.Properties["InstallTransition"]
          [PSCustomObject]@{
            KeyPath = $_.PSPath
            KeyName = $_.PSChildName
            DisplayName = [string]$displayNameProperty.Value
            Publisher = [string]$properties.PSObject.Properties["Publisher"].Value
            DisplayVersion = [string]$properties.PSObject.Properties["DisplayVersion"].Value
            InstallLocation = [string]$properties.PSObject.Properties["InstallLocation"].Value
            UninstallString = [string]$properties.PSObject.Properties["UninstallString"].Value
            MainBinaryName = [string]$properties.PSObject.Properties["MainBinaryName"].Value
            InstallTransition = if ($null -eq $transitionProperty) { "" } else { [string]$transitionProperty.Value }
          }
        }
      }
  )
}

function Get-OneCurrentUserUninstallEntry([string]$ExpectedVersion, [string]$InstallDirectory) {
  $entries = @(Get-CurrentUserUninstallEntries)
  if ($entries.Count -ne 1) {
    throw "Expected exactly one current-user ai-security-scanner uninstall record, found $($entries.Count)."
  }
  $entry = $entries[0]
  if (-not [String]::Equals($entry.KeyName, "ai-security-scanner", [StringComparison]::Ordinal) -or
      -not [String]::Equals($entry.DisplayName, "ai-security-scanner", [StringComparison]::Ordinal) -or
      -not [String]::Equals($entry.Publisher, "ai-security-scanner contributors", [StringComparison]::Ordinal) -or
      -not [String]::Equals($entry.MainBinaryName, "ai-security-scanner.exe", [StringComparison]::Ordinal)) {
    throw "The current-user uninstall record is not the exact product registration."
  }
  if (-not [String]::Equals($entry.DisplayVersion, $ExpectedVersion, [StringComparison]::Ordinal)) {
    throw "The current-user uninstall record has DisplayVersion $($entry.DisplayVersion), expected $ExpectedVersion."
  }
  $expectedUninstaller = Join-Path ([IO.Path]::GetFullPath($InstallDirectory)) "uninstall.exe"
  $expectedQuotedUninstallString = '"' + [IO.Path]::GetFullPath($expectedUninstaller) + '"'
  if (-not [String]::Equals(
      $entry.UninstallString,
      $expectedQuotedUninstallString,
      [StringComparison]::OrdinalIgnoreCase
    )) {
    throw "The current-user uninstall record does not contain the exact quoted UninstallString."
  }
  $expectedQuotedInstallLocation = '"' + [IO.Path]::GetFullPath($InstallDirectory) + '"'
  if (-not [String]::Equals(
      $entry.InstallLocation,
      $expectedQuotedInstallLocation,
      [StringComparison]::OrdinalIgnoreCase
    )) {
    throw "The current-user uninstall record does not contain the exact quoted InstallLocation."
  }
  return $entry
}

function Get-PrivateDataSnapshot([string]$Root) {
  Assert-RealDirectory $Root "Private application data root" | Out-Null
  $rootPath = [IO.Path]::GetFullPath($Root)
  $items = @(Get-ChildItem -LiteralPath $rootPath -Force -Recurse)
  if ($items.Count -gt $maximumDataSnapshotFiles * 2) {
    throw "Private application data tree exceeded its entry bound."
  }
  $files = [Collections.Generic.List[object]]::new()
  [int64]$totalBytes = 0
  foreach ($item in $items) {
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
      throw "Private application data contains a reparse point."
    }
    $fullPath = [IO.Path]::GetFullPath($item.FullName)
    if (-not $fullPath.StartsWith($rootPath + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
      throw "Private application data entry escaped its exact root."
    }
    if (-not $item.PSIsContainer) {
      if ($files.Count -eq $maximumDataSnapshotFiles) {
        throw "Private application data exceeded its file-count bound."
      }
      $fileProof = Get-NoFollowFileSha256Proof $fullPath "Private application data file" $maximumDataSnapshotBytes
      $totalBytes += [int64]$fileProof.Length
      if ($totalBytes -gt $maximumDataSnapshotBytes) {
        throw "Private application data exceeded its byte bound."
      }
      $relative = [IO.Path]::GetRelativePath($rootPath, $fullPath).Replace('\', '/')
      $files.Add([ordered]@{
        path = $relative
        bytes = [int64]$fileProof.Length
        sha256 = [string]$fileProof.Sha256
      })
    }
  }
  $ordered = @($files | Sort-Object { $_.path })
  $encoded = ConvertTo-Json -InputObject $ordered -Compress -Depth 5
  $digestBytes = [Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($encoded))
  return [ordered]@{
    fileCount = $ordered.Count
    totalBytes = $totalBytes
    digest = [Convert]::ToHexString($digestBytes).ToLowerInvariant()
  }
}

function Download-PinnedPriorInstaller([string]$Destination) {
  $handler = [Net.Http.HttpClientHandler]::new()
  $handler.AllowAutoRedirect = $true
  $handler.MaxAutomaticRedirections = 5
  $handler.UseCookies = $false
  $client = [Net.Http.HttpClient]::new($handler)
  $client.Timeout = [TimeSpan]::FromMinutes(5)
  try {
    $request = [Net.Http.HttpRequestMessage]::new([Net.Http.HttpMethod]::Get, $priorInstallerUrl)
    $response = $client.Send($request, [Net.Http.HttpCompletionOption]::ResponseHeadersRead)
    try {
      $response.EnsureSuccessStatusCode() | Out-Null
      if ($null -ne $response.Content.Headers.ContentLength -and
          ($response.Content.Headers.ContentLength -ne $priorInstallerBytes -or
           $response.Content.Headers.ContentLength -gt $maximumPriorDownloadBytes)) {
        throw "Pinned N-1 installer Content-Length is not the checked-in release length."
      }
      $input = $response.Content.ReadAsStream()
      $output = [IO.FileStream]::new(
        $Destination,
        [IO.FileMode]::CreateNew,
        [IO.FileAccess]::Write,
        [IO.FileShare]::None
      )
      try {
        [byte[]]$buffer = [byte[]]::new(64 * 1024)
        [int64]$written = 0
        while (($read = $input.Read($buffer, 0, $buffer.Length)) -gt 0) {
          $written += $read
          if ($written -gt $maximumPriorDownloadBytes) {
            throw "Pinned N-1 installer download exceeded its byte bound."
          }
          $output.Write($buffer, 0, $read)
        }
        $output.Flush($true)
      } finally {
        $output.Dispose()
        $input.Dispose()
      }
    } finally {
      $response.Dispose()
      $request.Dispose()
    }
  } finally {
    $client.Dispose()
    $handler.Dispose()
  }
  $proof = Get-NoFollowFileSha256Proof $Destination "Downloaded pinned N-1 NSIS installer" $maximumPriorDownloadBytes
  if ($proof.Length -ne $priorInstallerBytes -or $proof.Sha256 -cne $priorInstallerSha256) {
    throw "Downloaded N-1 NSIS installer differs from the checked-in immutable release pin."
  }
  return $proof
}

function Remove-ExactTree([string]$Path, [string]$Parent, [string]$ExpectedName) {
  Assert-ExactChildPath $Parent $Path $ExpectedName "Cleanup tree" | Out-Null
  if (Test-Path -LiteralPath $Path) {
    Assert-RealDirectory $Path "Cleanup tree" | Out-Null
    Remove-Item -LiteralPath $Path -Recurse -Force
  }
  if (Test-Path -LiteralPath $Path) {
    throw "Exact qualification cleanup tree remains: $Path"
  }
}

$artifactRoot = (Resolve-Path -LiteralPath $ArtifactDirectory).Path
Assert-RealDirectory $artifactRoot "Release artifact directory" | Out-Null
$runnerTemp = [IO.Path]::GetFullPath($env:RUNNER_TEMP)
Assert-RealDirectory $runnerTemp "RUNNER_TEMP" | Out-Null
$workRoot = Assert-ExactChildPath $runnerTemp $WorkDirectory "ai-security-scanner-nsis-upgrade-evidence" "Qualification work directory"
New-Item -ItemType Directory -Path $workRoot -Force | Out-Null
Assert-RealDirectory $workRoot "Qualification work directory" | Out-Null
$installDirectory = Assert-ExactChildPath $runnerTemp (Join-Path $runnerTemp "ai-security-scanner-nsis-upgrade-installed") "ai-security-scanner-nsis-upgrade-installed" "Qualification install directory"
$localApplicationData = [IO.Path]::GetFullPath(
  [Environment]::GetFolderPath([Environment+SpecialFolder]::LocalApplicationData)
)
Assert-RealDirectory $localApplicationData "OS-resolved LocalApplicationData" | Out-Null
$dataDirectory = Assert-ExactChildPath $localApplicationData (Join-Path $localApplicationData "dev.teddashh.ai-security-scanner") "dev.teddashh.ai-security-scanner" "Default application data directory"
$registrySentinelPath = "HKCU:\Software\dev.teddashh.ai-security-scanner\release-qualification\nsis-upgrade"
$priorInstallerPath = Assert-ExactChildPath $workRoot (Join-Path $workRoot $priorInstallerName) $priorInstallerName "Pinned prior installer"
$masterFrameworkReportPath = Assert-ExactChildPath $workRoot (
  Join-Path $workRoot "master-framework-report.json"
) "master-framework-report.json" "Retained master framework report"
$masterFrameworkBundlePath = Assert-ExactChildPath $workRoot (
  Join-Path $workRoot "master-framework-report.case.tar.gz"
) "master-framework-report.case.tar.gz" "Retained signed candidate case bundle"
$priorSignedCaseBundlePath = Assert-ExactChildPath $workRoot (
  Join-Path $workRoot "n-minus-one-before-upgrade.case.tar.gz"
) "n-minus-one-before-upgrade.case.tar.gz" "Retained signed N-1 case bundle"
$observationsPath = Assert-ExactChildPath $workRoot (
  Join-Path $workRoot "observations.json"
) "observations.json" "Qualification observations"

foreach ($freshPath in @(
  $installDirectory,
  $dataDirectory,
  $priorInstallerPath,
  $masterFrameworkReportPath,
  $masterFrameworkBundlePath,
  $priorSignedCaseBundlePath,
  $observationsPath,
  $registrySentinelPath
)) {
  if (Test-Path -LiteralPath $freshPath) {
    throw "Windows NSIS upgrade qualification requires a fresh exact namespace: $freshPath"
  }
}
if (@(Get-CurrentUserUninstallEntries).Count -ne 0) {
  throw "Windows NSIS upgrade qualification requires no existing current-user product registration."
}
if ($CurrentVersion -notmatch '^[0-9]+\.[0-9]+\.[0-9]+$' -or $CurrentVersion -eq $priorVersion) {
  throw "Current release version is malformed or not newer than the pinned N-1 fixture."
}

$manifestPath = Join-Path $artifactRoot "installers-windows-x86_64.json"
$installerManifest = Read-BoundedJsonFile $manifestPath "Candidate installer manifest" (1024 * 1024)
$candidateInstallers = @($installerManifest.installers | Where-Object { $_.bundleType -eq "nsis" })
if ($installerManifest.version -cne $CurrentVersion -or $candidateInstallers.Count -ne 1 -or
    [IO.Path]::GetFileName([string]$candidateInstallers[0].file) -cne [string]$candidateInstallers[0].file) {
  throw "Candidate release artifact does not contain one flat NSIS installer for the requested version."
}
$candidateInstallerPath = (Resolve-Path -LiteralPath (Join-Path $artifactRoot $candidateInstallers[0].file)).Path
if (-not [String]::Equals([IO.Path]::GetDirectoryName($candidateInstallerPath), $artifactRoot, [StringComparison]::OrdinalIgnoreCase)) {
  throw "Candidate NSIS installer escaped the downloaded release artifact directory."
}
$candidateInstallerItem = Get-NoFollowFileSha256Proof $candidateInstallerPath "Candidate NSIS installer" (256 * 1024 * 1024)
$candidateInstallerSha256 = [string]$candidateInstallerItem.Sha256
if ($candidateInstallerItem.Length -ne [int64]$candidateInstallers[0].bytes -or
    $candidateInstallerSha256 -cne [string]$candidateInstallers[0].sha256) {
  throw "Candidate NSIS installer differs from its release manifest."
}

$primaryFailure = $null
$cleanupFailures = [Collections.Generic.List[string]]::new()
$happyPathUninstalled = $false
$observations = $null
$activeUninstaller = $null
try {
  $priorInstallerProof = Download-PinnedPriorInstaller $priorInstallerPath
  Invoke-ExactProcess $priorInstallerPath @("/S", "/D=$installDirectory") 180000 "Pinned N-1 NSIS installation" -ExpectedExecutableProof $priorInstallerProof | Out-Null
  Assert-RealDirectory $installDirectory "N-1 installation directory" | Out-Null
  $priorDesktop = Find-OneInstalledFile $installDirectory "ai-security-scanner.exe"
  $priorCli = Find-OneInstalledFile $installDirectory "ai-security-scanner-cli.exe"
  $priorUninstaller = Find-OneInstalledFile $installDirectory "uninstall.exe"
  $activeUninstaller = $priorUninstaller
  $priorUninstallerSha256 = Get-LowerSha256 $priorUninstaller (512 * 1024 * 1024)
  $priorCliVersion = Get-CliVersion $priorCli "N-1 CLI"
  if ($priorCliVersion -cne $priorVersion) {
    throw "Pinned N-1 installer did not install CLI version $priorVersion."
  }
  $priorRegistry = Get-OneCurrentUserUninstallEntry $priorVersion $installDirectory

  $runtimeManifests = @(
    Get-ChildItem -LiteralPath $installDirectory -Filter "manifest.json" -File -Recurse -Force |
      Where-Object { $_.FullName -match '(?i)[\\/]managed-runtime[\\/]manifest\.json$' }
  )
  if ($runtimeManifests.Count -ne 1 -or
      (Get-LowerSha256 $runtimeManifests[0].FullName (1024 * 1024)) -cne $priorRuntimeManifestSha256) {
    throw "Pinned N-1 installation does not contain the immutable Windows managed-runtime manifest."
  }

  New-Item -ItemType Directory -Path $dataDirectory -Force | Out-Null
  $sentinelPath = Join-Path $dataDirectory "nsis-upgrade-data-preservation-sentinel.json"
  [IO.File]::WriteAllText(
    $sentinelPath,
    '{"schema":"ai-security-scanner.release-qualification/v1","value":"synthetic-non-sensitive"}',
    [Text.UTF8Encoding]::new($false)
  )
  New-Item -ItemType Directory -Path $registrySentinelPath -Force | Out-Null
  New-ItemProperty -LiteralPath $registrySentinelPath -Name "value" -Value "synthetic-non-sensitive" -PropertyType String -Force | Out-Null

  $demoCase = Invoke-CliJson $priorCli @(
    "--json", "--data-dir", $dataDirectory, "case", "seed-demo"
  ) "N-1 synthetic case seed"
  if ([string]::IsNullOrWhiteSpace([string]$demoCase.id) -or @($demoCase.scan_runs).Count -lt 1) {
    throw "N-1 CLI did not create one exportable synthetic demo case."
  }
  $caseId = [string]$demoCase.id
  $runId = [string]$demoCase.scan_runs[0].id
  $beforeBundle = $priorSignedCaseBundlePath
  Invoke-CliJson $priorCli @(
    "--json", "--data-dir", $dataDirectory,
    "export", "create", "--case-id", $caseId, "--run-id", $runId,
    "--format", "case-bundle", "--destination", $beforeBundle
  ) "N-1 synthetic case export" | Out-Null
  $beforeVerification = Invoke-CliJson $priorCli @(
    "--json", "--data-dir", $dataDirectory, "export", "verify", "--path", $beforeBundle
  ) "N-1 synthetic bundle verification"
  if ($beforeVerification.valid -ne $true) {
    throw "N-1 synthetic case bundle did not verify."
  }
  $priorSignedCaseBundleProof = Get-NoFollowFileSha256Proof (
    $priorSignedCaseBundlePath
  ) "Retained signed N-1 case bundle" $maximumRetainedCaseBundleBytes
  $privateSigningKeyPath = Join-Path $dataDirectory "integrity-signing-key"
  Assert-RealFile $privateSigningKeyPath "Synthetic-case integrity signing key" (64 * 1024) | Out-Null
  $privateSigningKeySha256Before = Get-LowerSha256 $privateSigningKeyPath (64 * 1024)

  $providerNamespace = $priorRuntimeManifestSha256.Substring(0, 16)
  $providerHome = Join-Path $dataDirectory "managed-runtime\provider-home\$providerNamespace"
  $providerWslStorage = Join-Path $providerHome "data\containers\podman\machine\wsl\wsldist"
  New-Item -ItemType Directory -Path $providerWslStorage -Force | Out-Null
  $providerSentinel = Join-Path $providerWslStorage "nsis-upgrade-ghost-sentinel.json"
  [IO.File]::WriteAllText(
    $providerSentinel,
    '{"schema":"ai-security-scanner.release-qualification/managed-runtime-ghost-v1","registered_wsl":false}',
    [Text.UTF8Encoding]::new($false)
  )
  $priorVersionDirectoryName = "podman-machine-5.8.2-$providerNamespace"
  $priorVersionDirectory = Join-Path $dataDirectory "managed-runtime\versions\$priorVersionDirectoryName"
  if (Test-Path -LiteralPath $priorVersionDirectory) {
    throw "Normal upgrade fixture unexpectedly contains the exact N-1 versions payload directory."
  }

  $beforeSnapshot = Get-PrivateDataSnapshot $dataDirectory
  Invoke-ExactProcess $candidateInstallerPath @("/S", "/D=$installDirectory") 180000 "Candidate silent NSIS upgrade" -ExpectedExecutableProof $candidateInstallerItem | Out-Null
  Assert-RealFile $priorDesktop "Candidate desktop at the N-1 canonical path" (512 * 1024 * 1024) | Out-Null
  $candidateCli = Find-OneInstalledFile $installDirectory "ai-security-scanner-cli.exe"
  $candidateUninstaller = Find-OneInstalledFile $installDirectory "uninstall.exe"
  $activeUninstaller = $candidateUninstaller
  $candidateCliVersion = Get-CliVersion $candidateCli "Candidate CLI"
  if ($candidateCliVersion -cne $CurrentVersion) {
    throw "NSIS upgrade left CLI version $candidateCliVersion instead of $CurrentVersion."
  }
  $candidateRegistry = Get-OneCurrentUserUninstallEntry $CurrentVersion $installDirectory
  if (-not [String]::Equals($candidateRegistry.KeyName, $priorRegistry.KeyName, [StringComparison]::Ordinal)) {
    throw "NSIS upgrade replaced the product registry identity instead of updating it."
  }
  if ($candidateRegistry.InstallTransition -cne "uninstalled-$priorVersion") {
    throw "NSIS upgrade did not prove that the normal N-1 uninstaller completed."
  }
  Invoke-ExactProcess $candidateInstallerPath @("/S", "/D=$installDirectory") 180000 "Candidate same-version silent NSIS reinstall" -ExpectedExecutableProof $candidateInstallerItem | Out-Null
  Assert-RealFile $priorDesktop "Reinstalled candidate desktop at the canonical path" (512 * 1024 * 1024) | Out-Null
  $candidateCli = Find-OneInstalledFile $installDirectory "ai-security-scanner-cli.exe"
  $candidateUninstaller = Find-OneInstalledFile $installDirectory "uninstall.exe"
  $activeUninstaller = $candidateUninstaller
  if ((Get-CliVersion $candidateCli "Same-version reinstalled candidate CLI") -cne $CurrentVersion) {
    throw "Same-version silent reinstall changed the candidate CLI version."
  }
  $candidateRegistry = Get-OneCurrentUserUninstallEntry $CurrentVersion $installDirectory
  if (-not [String]::Equals($candidateRegistry.KeyName, $priorRegistry.KeyName, [StringComparison]::Ordinal) -or
      $candidateRegistry.InstallTransition -cne "uninstalled-$priorVersion") {
    throw "Same-version silent reinstall did not preserve the bounded N-1 transition receipt."
  }
  $candidateUninstallerSha256 = Get-LowerSha256 $candidateUninstaller (512 * 1024 * 1024)
  if ($candidateUninstallerSha256 -ceq $priorUninstallerSha256) {
    throw "NSIS upgrade did not replace the N-1 uninstaller."
  }

  $afterSnapshot = Get-PrivateDataSnapshot $dataDirectory
  if ($beforeSnapshot.digest -cne $afterSnapshot.digest -or
      $beforeSnapshot.fileCount -ne $afterSnapshot.fileCount -or
      $beforeSnapshot.totalBytes -ne $afterSnapshot.totalBytes) {
    throw "Candidate NSIS installer changed private application data during upgrade."
  }
  if (-not (Test-Path -LiteralPath $sentinelPath -PathType Leaf) -or
      -not (Test-Path -LiteralPath $providerSentinel -PathType Leaf) -or
      -not (Test-Path -LiteralPath $registrySentinelPath -PathType Container) -or
      (Get-ItemPropertyValue -LiteralPath $registrySentinelPath -Name "value") -cne "synthetic-non-sensitive" -or
      (Test-Path -LiteralPath $priorVersionDirectory)) {
    throw "NSIS upgrade did not preserve the bounded data, registry, and absent N-1 payload fixture."
  }
  $privateSigningKeySha256AfterInstaller = Get-LowerSha256 $privateSigningKeyPath (64 * 1024)
  if ($privateSigningKeySha256AfterInstaller -cne $privateSigningKeySha256Before) {
    throw "NSIS upgrade changed the private integrity signing material."
  }

  $candidateSigningIdentity = Invoke-CliJson $candidateCli @(
    "--json", "--data-dir", $dataDirectory, "export", "identity", "show"
  ) "Candidate durable export identity adoption"
  Assert-ExactJsonProperties $candidateSigningIdentity @(
    "algorithm",
    "key_id",
    "public_key_base64",
    "established_at",
    "continuity_event",
    "previous_key_id",
    "notice"
  ) "Public signing identity summary"
  $identityDocumentPath = Assert-ExactChildPath $dataDirectory (
    Join-Path $dataDirectory "integrity-signing-key.identity.json"
  ) "integrity-signing-key.identity.json" "Durable export identity document"
  $identityAnchorPath = Assert-ExactChildPath $dataDirectory (
    Join-Path $dataDirectory "integrity-signing-key.identity-anchor.json"
  ) "integrity-signing-key.identity-anchor.json" "Durable export identity anchor"
  $rotationIntentPath = Assert-ExactChildPath $dataDirectory (
    Join-Path $dataDirectory "integrity-signing-key.rotation-intent.json"
  ) "integrity-signing-key.rotation-intent.json" "Signing identity rotation intent"
  if ($candidateSigningIdentity.continuity_event -cne "legacy_key_adopted" -or
      $candidateSigningIdentity.algorithm -cne "Ed25519" -or
      $null -ne $candidateSigningIdentity.previous_key_id -or
      [string]$candidateSigningIdentity.key_id -cne [string]$beforeVerification.signer_key_id -or
      [string]$candidateSigningIdentity.public_key_base64 -cne [string]$beforeVerification.public_key_base64) {
    throw "Candidate did not durably adopt the real v0.1.7 export-signing identity."
  }
  $privateSigningKeyItem = Assert-OwnerOnlyFullControlFile $privateSigningKeyPath "Managed export signing key" 32
  $identityDocumentItem = Assert-OwnerOnlyFullControlFile $identityDocumentPath "Durable export identity document" (64 * 1024)
  $identityAnchorItem = Assert-OwnerOnlyFullControlFile $identityAnchorPath "Durable export identity anchor" (64 * 1024)
  if ($privateSigningKeyItem.Length -ne 32) {
    throw "Managed export signing key is not the exact 32-byte Ed25519 seed."
  }
  if (Test-Path -LiteralPath $rotationIntentPath) {
    throw "Successful legacy signing-key adoption left a rotation intent behind."
  }
  $identityDocumentRecord = Read-BoundedUtf8File $identityDocumentPath "Durable export identity document" (64 * 1024)
  $identityAnchorRecord = Read-BoundedUtf8File $identityAnchorPath "Durable export identity anchor" (64 * 1024)
  try {
    $identityDocument = $identityDocumentRecord.Text | ConvertFrom-Json -DateKind String
    $identityAnchor = $identityAnchorRecord.Text | ConvertFrom-Json -DateKind String
  } catch {
    throw "Durable export identity document or anchor is invalid JSON."
  }
  $identityFields = @(
    "schema_version",
    "algorithm",
    "key_id",
    "public_key_base64",
    "established_at",
    "continuity_event",
    "self_signature_base64",
    "notice"
  )
  Assert-ExactJsonProperties $identityDocument $identityFields "Durable export identity document"
  Assert-ExactJsonProperties $identityAnchor @(
    "schema_version", "identity_document_sha256", "identity"
  ) "Durable export identity anchor"
  Assert-ExactJsonProperties $identityAnchor.identity $identityFields "Anchored export identity"
  $identityJsonDocument = [Text.Json.JsonDocument]::Parse($identityDocumentRecord.Text)
  try {
    $identityJsonRoot = $identityJsonDocument.RootElement
    $identityDocumentEvidence = [ordered]@{
      schema_version = $identityJsonRoot.GetProperty("schema_version").GetString()
      algorithm = $identityJsonRoot.GetProperty("algorithm").GetString()
      key_id = $identityJsonRoot.GetProperty("key_id").GetString()
      public_key_base64 = $identityJsonRoot.GetProperty("public_key_base64").GetString()
      established_at = $identityJsonRoot.GetProperty("established_at").GetString()
      continuity_event = $identityJsonRoot.GetProperty("continuity_event").GetString()
      self_signature_base64 = $identityJsonRoot.GetProperty("self_signature_base64").GetString()
      notice = $identityJsonRoot.GetProperty("notice").GetString()
    }
  } finally {
    $identityJsonDocument.Dispose()
  }
  $identityCompactBytes = Convert-JsonTextToCompactUtf8Bytes $identityDocumentRecord.Text
  $anchorIdentityCompactBytes = Convert-JsonTextToCompactUtf8Bytes $identityAnchorRecord.Text "identity"
  $identityCompactJson = [Text.Encoding]::UTF8.GetString($identityCompactBytes)
  $anchorIdentityCompactJson = [Text.Encoding]::UTF8.GetString($anchorIdentityCompactBytes)
  $identityDocumentSha256 = Get-LowerSha256Bytes $identityCompactBytes
  $anchorIdentitySha256 = Get-LowerSha256Bytes $anchorIdentityCompactBytes
  try {
    $publicKeyBytes = [Convert]::FromBase64String([string]$identityDocument.public_key_base64)
    $selfSignatureBytes = [Convert]::FromBase64String([string]$identityDocument.self_signature_base64)
  } catch {
    throw "Durable export identity contains malformed base64."
  }
  if ($identityDocument.schema_version -cne "1" -or
      $identityAnchor.schema_version -cne "1" -or
      $identityDocument.algorithm -cne "Ed25519" -or
      $identityDocument.continuity_event -cne "legacy_key_adopted" -or
      $publicKeyBytes.Length -ne 32 -or $selfSignatureBytes.Length -ne 64 -or
      [string]$identityDocument.key_id -cnotmatch '^[0-9a-f]{64}$' -or
      [string]$identityDocument.key_id -cne [string]$beforeVerification.signer_key_id -or
      [string]$identityDocument.public_key_base64 -cne [string]$beforeVerification.public_key_base64 -or
      $identityCompactJson -cne $anchorIdentityCompactJson -or
      $identityDocumentSha256 -cne $anchorIdentitySha256 -or
      [string]$identityAnchor.identity_document_sha256 -cne $identityDocumentSha256 -or
      [string]$identityDocument.established_at -cne [string]$candidateSigningIdentity.established_at -or
      [string]$identityDocument.notice -cne [string]$candidateSigningIdentity.notice -or
      (Get-LowerSha256 $privateSigningKeyPath (64 * 1024)) -cne $privateSigningKeySha256Before) {
    throw "Durable export identity document and anchor do not bind the preserved v0.1.7 key."
  }

  $candidateCase = Invoke-CliJson $candidateCli @(
    "--json", "--data-dir", $dataDirectory, "case", "show", $caseId
  ) "Candidate synthetic case read"
  if (-not [String]::Equals([string]$candidateCase.id, $caseId, [StringComparison]::Ordinal)) {
    throw "Candidate CLI did not preserve the synthetic case identity."
  }
  $afterBundle = $masterFrameworkBundlePath
  Invoke-CliJson $candidateCli @(
    "--json", "--data-dir", $dataDirectory,
    "export", "create", "--case-id", $caseId, "--run-id", $runId,
    "--format", "case-bundle", "--destination", $afterBundle
  ) "Candidate synthetic case export" | Out-Null
  $afterVerification = Invoke-CliJson $candidateCli @(
    "--json", "--data-dir", $dataDirectory, "export", "verify", "--path", $afterBundle
  ) "Candidate synthetic bundle verification"
  if ($afterVerification.valid -ne $true -or
      [string]$afterVerification.signer_key_id -cne [string]$beforeVerification.signer_key_id -or
      [string]$afterVerification.public_key_base64 -cne [string]$beforeVerification.public_key_base64 -or
      (Get-LowerSha256 $privateSigningKeyPath (64 * 1024)) -cne $privateSigningKeySha256Before -or
      (Test-Path -LiteralPath $rotationIntentPath)) {
    throw "Candidate export did not preserve and reuse the N-1 integrity signing identity."
  }
  $masterFrameworkBundleProof = Get-NoFollowFileSha256Proof (
    $masterFrameworkBundlePath
  ) "Retained signed candidate case bundle" $maximumRetainedCaseBundleBytes

  Invoke-CliJson $candidateCli @(
    "--json", "--data-dir", $dataDirectory,
    "export", "create", "--case-id", $caseId, "--run-id", $runId,
    "--format", "framework-report", "--destination", $masterFrameworkReportPath
  ) "Candidate installed-artifact master framework report export" | Out-Null
  $masterFrameworkReportProof = Get-NoFollowFileSha256Proof (
    $masterFrameworkReportPath
  ) "Installed-artifact master framework report" (4 * 1024 * 1024)
  $masterFrameworkReport = Read-BoundedJsonFile (
    $masterFrameworkReportPath
  ) "Installed-artifact master framework report" (4 * 1024 * 1024)
  Assert-ExactJsonProperties $masterFrameworkReport @(
    "schema_version",
    "product_name",
    "product_version",
    "export_kind",
    "case_id",
    "selected_run_id",
    "selected_run_sequence",
    "selected_run_recorded_at",
    "knowledge_date",
    "notice",
    "coverage",
    "declared_ai_context",
    "observation_provenance",
    "frameworks",
    "unrecognized_relationships"
  ) "Installed-artifact master framework report"
  $expectedReportNotice = "This report groups preliminary scanner observations by related framework coordinate. It is not an audit, certification, attestation, compliance determination, implementation assessment, score, pass, or fail. Missing relationships are unknown whenever coverage is incomplete."
  $frameworks = @($masterFrameworkReport.frameworks)
  if ($masterFrameworkReport.schema_version -cne "1.1.0" -or
      $masterFrameworkReport.product_name -cne "ai-security-scanner" -or
      $masterFrameworkReport.product_version -cne $CurrentVersion -or
      $masterFrameworkReport.export_kind -cne "master_framework_relationship_report" -or
      $masterFrameworkReport.case_id -cne $caseId -or
      $masterFrameworkReport.selected_run_id -cne $runId -or
      $masterFrameworkReport.notice -cne $expectedReportNotice -or
      $masterFrameworkReport.coverage.state -cne "incomplete_or_unknown" -or
      $masterFrameworkReport.coverage.current_coverage_ledger_has_unknown_or_incomplete_entries -ne $true -or
      @($masterFrameworkReport.coverage.limitations).Count -lt 1 -or
      $masterFrameworkReport.declared_ai_context.aidefend_applicability -cne "unknown" -or
      $frameworks.Count -ne 3 -or
      $frameworks[0].framework -cne "NIST CSF" -or $frameworks[0].expected_version -cne "2.0" -or
      [int]$frameworks[0].relationship_count -lt 1 -or
      $frameworks[1].framework -cne "ISO/IEC 27001" -or $frameworks[1].expected_version -cne "2022" -or
      [int]$frameworks[1].relationship_count -lt 1 -or
      $frameworks[2].framework -cne "AIDEFEND" -or $frameworks[2].expected_version -cne "1.20260805" -or
      $frameworks[2].state -cne "unknown_due_to_unanswered_context" -or
      [int]$frameworks[2].relationship_count -ne 0) {
    throw "Installed candidate did not emit the fixed truthful NIST, ISO 27001, and AIDEFEND master report contract."
  }
  $masterReportBundleEntries = @(
    $afterVerification.manifest.entries |
      Where-Object { [string]$_.path -ceq "exports/master-framework-report.json" }
  )
  if ($masterReportBundleEntries.Count -ne 1) {
    throw "Verified candidate bundle does not contain exactly one master framework report entry."
  }
  $masterReportBundleEntry = $masterReportBundleEntries[0]
  Assert-ExactJsonProperties $masterReportBundleEntry @(
    "path", "media_type", "sha256", "byte_length", "contains_sensitive_data"
  ) "Signed bundle master framework report entry"
  if ([string]$masterReportBundleEntry.media_type -cne "application/json" -or
      [string]$masterReportBundleEntry.sha256 -cne [string]$masterFrameworkReportProof.Sha256 -or
      [int64]$masterReportBundleEntry.byte_length -ne [int64]$masterFrameworkReportProof.Length) {
    throw "Standalone master framework report bytes do not exactly match the verified signed bundle entry."
  }
  $masterFrameworkReportObservation = [ordered]@{
    reportFile = "master-framework-report.json"
    reportBytes = [int64]$masterFrameworkReportProof.Length
    reportSha256 = [string]$masterFrameworkReportProof.Sha256
    bundleEntryPath = [string]$masterReportBundleEntry.path
    bundleEntryBytes = [int64]$masterReportBundleEntry.byte_length
    bundleEntrySha256 = [string]$masterReportBundleEntry.sha256
    exactBundleEntryMatch = $true
    schemaVersion = [string]$masterFrameworkReport.schema_version
    product = [string]$masterFrameworkReport.product_name
    productVersion = [string]$masterFrameworkReport.product_version
    caseId = [string]$masterFrameworkReport.case_id
    runId = [string]$masterFrameworkReport.selected_run_id
    frameworkKeys = @("nist_csf", "iso_iec_27001", "aidefend")
    truthfulUnknownCoverage = $true
    noComplianceOutcomeClaims = $true
  }

  Invoke-ExactProcess $candidateUninstaller @("/S") 180000 "Candidate NSIS uninstall" | Out-Null
  $happyPathUninstalled = $true
  $activeUninstaller = $null
  if (@(Get-CurrentUserUninstallEntries).Count -ne 0) {
    throw "Candidate NSIS uninstall left its current-user product registration behind."
  }
  if (Test-Path -LiteralPath $installDirectory) {
    Remove-ExactTree $installDirectory $runnerTemp "ai-security-scanner-nsis-upgrade-installed"
  }
  Remove-ExactTree $dataDirectory $localApplicationData "dev.teddashh.ai-security-scanner"
  Remove-Item -LiteralPath $registrySentinelPath -Recurse -Force
  if (Test-Path -LiteralPath $registrySentinelPath) {
    throw "Qualification registry sentinel remains after exact cleanup."
  }

  $observations = [ordered]@{
    schemaVersion = 1
    scenario = "real_n_minus_one_nsis_upgrade"
    platform = "windows-x86_64"
    runner = "windows-2025"
    priorRelease = [ordered]@{
      version = $priorVersion
      tag = $priorTag
      installerFile = $priorInstallerName
      installerBytes = $priorInstallerBytes
      installerSha256 = $priorInstallerSha256
      downloadUrl = $priorInstallerUrl
      runtimeManifestSha256 = $priorRuntimeManifestSha256
      machineImageSha256 = $priorMachineImageSha256
    }
    candidate = [ordered]@{
      version = $CurrentVersion
      installerFile = [string]$candidateInstallers[0].file
      installerBytes = [int64]$candidateInstallers[0].bytes
      installerSha256 = $candidateInstallerSha256
    }
    installation = [ordered]@{
      priorCliVersion = $priorCliVersion
      candidateCliVersion = $candidateCliVersion
      sameCanonicalInstallDirectory = $true
      registryHive = "HKEY_CURRENT_USER"
      registryEntryIdentityPreserved = $true
      displayVersionUpdated = $true
      uninstallerReplaced = $true
      unattendedMode = "silent"
      sameVersionSilentReinstallCompleted = $true
      transitionReceiptSurvivedSameVersionReinstall = $true
      transitionReceipt = "uninstalled-$priorVersion"
    }
    dataPreservation = [ordered]@{
      defaultLocalDataDirectoryUsed = $true
      preInstallerFileCount = [int]$beforeSnapshot.fileCount
      preInstallerBytes = [int64]$beforeSnapshot.totalBytes
      exactPreInstallerSnapshotPreserved = $true
      sentinelPreserved = $true
      demoCaseId = $caseId
      demoCasePreserved = $true
      privateSigningMaterialBytePreserved = $true
      signingKeyIdBefore = [string]$beforeVerification.signer_key_id
      signingKeyIdAfter = [string]$afterVerification.signer_key_id
      publicKeyBase64Before = [string]$beforeVerification.public_key_base64
      publicKeyBase64After = [string]$afterVerification.public_key_base64
      privateSigningKeyProtected = $true
      publicIdentitySummaryExact = $true
      durableIdentityDocumentPresent = $true
      identityDocumentBytes = [int64]$identityDocumentItem.Length
      identityDocumentCompactSha256 = $identityDocumentSha256
      identityDocumentProtected = $true
      durableIdentityAnchorPresent = $true
      identityAnchorBytes = [int64]$identityAnchorItem.Length
      identityAnchorProtected = $true
      anchorSchemaVersion = [string]$identityAnchor.schema_version
      anchorIdentityDocumentSha256 = [string]$identityAnchor.identity_document_sha256
      anchorDigestVerified = $true
      anchorMatchesIdentityDocument = $true
      identitySelfSignatureVerifiedByCandidate = $true
      identityDocument = $identityDocumentEvidence
      rotationIntentAbsent = $true
      continuityEvent = [string]$candidateSigningIdentity.continuity_event
      identityKeyId = [string]$candidateSigningIdentity.key_id
      identityPublicKeyBase64 = [string]$candidateSigningIdentity.public_key_base64
      firstBundleValid = $true
      secondBundleValid = $true
    }
    masterFrameworkReport = $masterFrameworkReportObservation
    managedRuntimeFilesystemSentinel = [ordered]@{
      priorProviderNamespace = $providerNamespace
      priorVersionDirectory = $priorVersionDirectoryName
      priorVersionPayloadDirectoryAbsentBeforeUpgrade = $true
      priorVersionPayloadDirectoryAbsentAfterInstaller = $true
      providerHomeSentinelPreserved = $true
      registeredWslStateExercised = $false
    }
    cleanup = [ordered]@{
      candidateUninstalled = $true
      installDirectoryRemoved = $true
      privateDataRemoved = $true
      registrySentinelRemoved = $true
    }
  }
} catch {
  $primaryFailure = $_
} finally {
  if ($null -ne $primaryFailure) {
    if ($null -eq $activeUninstaller -and (Test-Path -LiteralPath $installDirectory -PathType Container)) {
      $fallback = @(
        Get-ChildItem -LiteralPath $installDirectory -Filter "uninstall.exe" -File -Recurse -Force |
          Where-Object { ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0 }
      )
      if ($fallback.Count -eq 1) {
        $activeUninstaller = $fallback[0].FullName
      }
    }
    if ($null -ne $activeUninstaller -and (Test-Path -LiteralPath $activeUninstaller -PathType Leaf)) {
      try {
        Invoke-ExactProcess $activeUninstaller @("/S") 180000 "Failure-path NSIS uninstall" | Out-Null
      } catch {
        $cleanupFailures.Add("NSIS uninstall: $($_.Exception.Message)")
      }
    }
    foreach ($cleanup in @(
      [ordered]@{ path = $installDirectory; parent = $runnerTemp; name = "ai-security-scanner-nsis-upgrade-installed" },
      [ordered]@{ path = $dataDirectory; parent = $localApplicationData; name = "dev.teddashh.ai-security-scanner" }
    )) {
      try {
        if (Test-Path -LiteralPath $cleanup.path) {
          Remove-ExactTree $cleanup.path $cleanup.parent $cleanup.name
        }
      } catch {
        $cleanupFailures.Add("exact tree cleanup: $($_.Exception.Message)")
      }
    }
    try {
      if (Test-Path -LiteralPath $registrySentinelPath) {
        Remove-Item -LiteralPath $registrySentinelPath -Recurse -Force
      }
    } catch {
      $cleanupFailures.Add("registry sentinel cleanup: $($_.Exception.Message)")
    }
  }
}

if ($null -ne $primaryFailure) {
  $suffix = if ($cleanupFailures.Count -eq 0) { "" } else { " Cleanup failure(s): $([String]::Join('; ', $cleanupFailures))" }
  throw [InvalidOperationException]::new($primaryFailure.Exception.Message + $suffix, $primaryFailure.Exception)
}
if (-not $happyPathUninstalled -or $null -eq $observations) {
  throw "Windows NSIS upgrade qualification did not reach its verified cleanup state."
}
$retainedMasterFrameworkBundleProof = Get-NoFollowFileSha256Proof (
  $masterFrameworkBundlePath
) "Retained signed candidate case bundle after cleanup" $maximumRetainedCaseBundleBytes
if ($retainedMasterFrameworkBundleProof.Length -ne $masterFrameworkBundleProof.Length -or
    $retainedMasterFrameworkBundleProof.Sha256 -cne $masterFrameworkBundleProof.Sha256) {
  throw "Retained signed candidate case bundle changed during qualification cleanup."
}
$retainedPriorSignedCaseBundleProof = Get-NoFollowFileSha256Proof (
  $priorSignedCaseBundlePath
) "Retained signed N-1 case bundle after cleanup" $maximumRetainedCaseBundleBytes
if ($retainedPriorSignedCaseBundleProof.Length -ne $priorSignedCaseBundleProof.Length -or
    $retainedPriorSignedCaseBundleProof.Sha256 -cne $priorSignedCaseBundleProof.Sha256) {
  throw "Retained signed N-1 case bundle changed during qualification cleanup."
}
$observations | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $observationsPath -Encoding utf8NoBOM -NoNewline
Add-Content -LiteralPath $observationsPath -Value "" -Encoding utf8NoBOM
