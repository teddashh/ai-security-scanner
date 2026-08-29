param(
  [Parameter(Mandatory = $true)][string]$ArtifactDirectory,
  [Parameter(Mandatory = $true)][string]$WorkDirectory,
  [Parameter(Mandatory = $true)][string]$CurrentVersion
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$priorVersion = "0.1.7"
$priorInstallerName = "ai-security-scanner_0.1.7_x64-setup.exe"
$priorInstallerBytes = 38730365
$priorInstallerSha256 = "4d2057ca4c008b46dc0195a792075e4b4b377c1909a7795b29efc30f9ae48b1a"
$priorInstallerUrl = "https://github.com/teddashh/ai-security-scanner/releases/download/v0.1.7/ai-security-scanner_0.1.7_x64-setup.exe"
$priorRuntimeManifestSha256 = "8b2257ace33ecb14bb0995044a4e6d2b4e71b314741601122801fbb59e7de13f"
$candidateRuntimeManifestExpectedSha256 = "a8112473e5d87655e6145ea5f6cff569c872329d2ec14bfb9463078abcb60e3a"
$priorMachineImageSha256 = "e2b6cbcadd8b41b708fecb58a246a20d737dee0ef26872a3f75b575f77eba968"
$priorProviderNamespace = $priorRuntimeManifestSha256.Substring(0, 16)
$oldMachineName = "assm1-win-x64-$($priorMachineImageSha256.Substring(0, 12))"
$oldDistributionName = "podman-$oldMachineName"
$oldVersionDirectoryName = "podman-machine-5.8.2-$priorProviderNamespace"
$maximumDownloadBytes = 64 * 1024 * 1024
$maximumSnapshotFiles = 4096
$maximumSnapshotBytes = 512 * 1024 * 1024
$processLeaseRelativePath = ".exclusive-process.lock"
$maximumWindowsPathUtf16CodeUnits = 32760
$maximumVerbatimWindowsPathUtf16CodeUnits = 32766

if ($CurrentVersion -cne "0.1.8") {
  throw "The bounded v0.1.7 ghost migration qualification applies only to candidate 0.1.8."
}

if ($null -eq ("GhostQualificationNativeMethods" -as [type])) {
  Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.ComTypes;
using System.Text;
using Microsoft.Win32.SafeHandles;

public static class GhostQualificationNativeMethods {
    public const uint GENERIC_READ = 0x80000000;
    public const uint FILE_READ_ATTRIBUTES = 0x00000080;
    public const uint FILE_SHARE_READ = 0x00000001;
    public const uint FILE_SHARE_WRITE = 0x00000002;
    public const uint OPEN_EXISTING = 3;
    public const uint FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000;
    public const uint FILE_FLAG_BACKUP_SEMANTICS = 0x02000000;

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
    public static extern uint GetSystemWindowsDirectoryW(StringBuilder buffer, uint size);

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
        out GhostQualificationByHandleFileInformation information);
}

[StructLayout(LayoutKind.Sequential)]
public struct GhostQualificationByHandleFileInformation {
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
  if (-not [String]::Equals([IO.Path]::GetDirectoryName($childPath), $parentPath, [StringComparison]::OrdinalIgnoreCase) -or
      -not [String]::Equals([IO.Path]::GetFileName($childPath), $ExpectedName, [StringComparison]::Ordinal)) {
    throw "$Label escaped its fixed parent or changed its fixed name."
  }
  return $childPath
}

function Assert-RealDirectory([string]$Path, [string]$Label) {
  $item = Get-Item -LiteralPath $Path -Force
  if (-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw "$Label is not one real directory."
  }
  return $item
}

function Get-OpenFileIdentity([IO.FileStream]$Stream) {
  $information = [GhostQualificationByHandleFileInformation]::new()
  if (-not [GhostQualificationNativeMethods]::GetFileInformationByHandle($Stream.SafeFileHandle, [ref]$information)) {
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

function Get-OpenDirectoryIdentity([Microsoft.Win32.SafeHandles.SafeFileHandle]$Handle) {
  if ($null -eq $Handle -or $Handle.IsInvalid -or $Handle.IsClosed) {
    throw "Qualification directory handle is not open."
  }
  $information = [GhostQualificationByHandleFileInformation]::new()
  if (-not [GhostQualificationNativeMethods]::GetFileInformationByHandle($Handle, [ref]$information)) {
    throw "Could not inspect the exact qualification directory handle."
  }
  return [ordered]@{
    attributes = [uint32]$information.FileAttributes
    volume = [uint32]$information.VolumeSerialNumber
    index = (([uint64]$information.FileIndexHigh -shl 32) -bor [uint64]$information.FileIndexLow)
  }
}

function Get-BoundedAbsoluteWindowsPath([string]$Path, [string]$Label) {
  if ([String]::IsNullOrWhiteSpace($Path) -or $Path.IndexOf([char]0) -ge 0) {
    throw "$Label is empty or contains a NUL code unit."
  }
  if ($Path.Length -gt $maximumWindowsPathUtf16CodeUnits -or
      -not [IO.Path]::IsPathFullyQualified($Path)) {
    throw "$Label is not one bounded absolute Windows path."
  }
  $full = [IO.Path]::GetFullPath($Path)
  if ($full.IndexOf([char]0) -ge 0 -or $full.Length -gt $maximumWindowsPathUtf16CodeUnits) {
    throw "$Label expanded beyond the Windows path bound."
  }
  return $full
}

function Get-VerbatimWindowsPath([string]$Path, [string]$Label) {
  $full = Get-BoundedAbsoluteWindowsPath $Path $Label
  if ($full.StartsWith("\\?\", [StringComparison]::Ordinal)) { return $full }
  $verbatim = if ($full.StartsWith("\\", [StringComparison]::Ordinal)) {
    "\\?\UNC\" + $full.Substring(2)
  } else {
    "\\?\" + $full
  }
  if ($verbatim.Length -gt $maximumVerbatimWindowsPathUtf16CodeUnits) {
    throw "$Label exceeds the Windows verbatim path bound."
  }
  return $verbatim
}

function Open-NoFollowSingleLinkFile(
  [string]$Path,
  [string]$Label,
  [uint64]$MaximumBytes = [uint64]::MaxValue
) {
  $verbatimPath = Get-VerbatimWindowsPath $Path $Label
  $handle = [GhostQualificationNativeMethods]::CreateFileW(
    $verbatimPath,
    [GhostQualificationNativeMethods]::GENERIC_READ,
    [GhostQualificationNativeMethods]::FILE_SHARE_READ,
    [IntPtr]::Zero,
    [GhostQualificationNativeMethods]::OPEN_EXISTING,
    [GhostQualificationNativeMethods]::FILE_FLAG_OPEN_REPARSE_POINT,
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

function Assert-ExactEmptyProcessLeaseFile([string]$Path, [string]$Label) {
  # This exception is intentionally separate from the generic evidence opener:
  # only the product's exact root process lease may be empty. Installer, key,
  # archive, receipt, and evidence proofs retain their >= 1-byte requirement.
  $verbatimPath = Get-VerbatimWindowsPath $Path $Label
  $handle = [GhostQualificationNativeMethods]::CreateFileW(
    $verbatimPath,
    [GhostQualificationNativeMethods]::GENERIC_READ,
    [GhostQualificationNativeMethods]::FILE_SHARE_READ,
    [IntPtr]::Zero,
    [GhostQualificationNativeMethods]::OPEN_EXISTING,
    [GhostQualificationNativeMethods]::FILE_FLAG_OPEN_REPARSE_POINT,
    [IntPtr]::Zero
  )
  if ($null -eq $handle -or $handle.IsInvalid) {
    $errorCode = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
    if ($null -ne $handle) { $handle.Dispose() }
    throw [ComponentModel.Win32Exception]::new(
      $errorCode,
      "$Label could not be opened without following reparse points"
    )
  }
  try {
    $stream = [IO.FileStream]::new($handle, [IO.FileAccess]::Read, 1, $false)
  } catch {
    $handle.Dispose()
    throw
  }
  try {
    $before = Get-OpenFileIdentity $stream
    if (($before.attributes -band [uint32][IO.FileAttributes]::Directory) -ne 0 -or
        ($before.attributes -band [uint32][IO.FileAttributes]::ReparsePoint) -ne 0 -or
        $before.links -ne 1 -or $before.bytes -ne 0) {
      throw "$Label is not the exact empty no-follow single-link process lease."
    }
    $after = Get-OpenFileIdentity $stream
    if ($before.attributes -ne $after.attributes -or $before.links -ne $after.links -or
        $before.bytes -ne $after.bytes -or $before.volume -ne $after.volume -or
        $before.index -ne $after.index) {
      throw "$Label changed while its exact no-follow handle was held."
    }
  } finally {
    $stream.Dispose()
    $handle.Dispose()
  }
}

function Open-NoFollowWindowsSystemFile(
  [string]$Path,
  [string]$Label,
  [uint64]$MaximumBytes = 512 * 1024 * 1024
) {
  $verbatimPath = Get-VerbatimWindowsPath $Path $Label
  $handle = [GhostQualificationNativeMethods]::CreateFileW(
    $verbatimPath,
    [GhostQualificationNativeMethods]::GENERIC_READ,
    [GhostQualificationNativeMethods]::FILE_SHARE_READ,
    [IntPtr]::Zero,
    [GhostQualificationNativeMethods]::OPEN_EXISTING,
    [GhostQualificationNativeMethods]::FILE_FLAG_OPEN_REPARSE_POINT,
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
    # Windows servicing legitimately exposes component-store files in System32
    # through hard links. This system-file-only opener therefore accepts one or
    # more links, while every installer, key, fixture, archive, and retained
    # evidence file continues to use Open-NoFollowSingleLinkFile above.
    if (($identity.attributes -band [uint32][IO.FileAttributes]::Directory) -ne 0 -or
        ($identity.attributes -band [uint32][IO.FileAttributes]::ReparsePoint) -ne 0 -or
        $identity.links -lt 1 -or $identity.bytes -lt 1 -or $identity.bytes -gt $MaximumBytes) {
      throw "$Label is not one bounded no-follow Windows system regular file."
    }
    return ,$stream
  } catch {
    $stream.Dispose()
    throw
  }
}

function Open-NoFollowRealDirectory([string]$Path, [string]$Label) {
  $verbatimPath = Get-VerbatimWindowsPath $Path $Label
  $handle = [GhostQualificationNativeMethods]::CreateFileW(
    $verbatimPath,
    [GhostQualificationNativeMethods]::FILE_READ_ATTRIBUTES,
    ([GhostQualificationNativeMethods]::FILE_SHARE_READ -bor [GhostQualificationNativeMethods]::FILE_SHARE_WRITE),
    [IntPtr]::Zero,
    [GhostQualificationNativeMethods]::OPEN_EXISTING,
    ([GhostQualificationNativeMethods]::FILE_FLAG_BACKUP_SEMANTICS -bor [GhostQualificationNativeMethods]::FILE_FLAG_OPEN_REPARSE_POINT),
    [IntPtr]::Zero
  )
  if ($null -eq $handle -or $handle.IsInvalid) {
    $errorCode = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
    if ($null -ne $handle) { $handle.Dispose() }
    throw [ComponentModel.Win32Exception]::new($errorCode, "$Label could not be opened without following reparse points")
  }
  try {
    $identity = Get-OpenDirectoryIdentity $handle
    if (($identity.attributes -band [uint32][IO.FileAttributes]::Directory) -eq 0 -or
        ($identity.attributes -band [uint32][IO.FileAttributes]::ReparsePoint) -ne 0) {
      throw "$Label is not one no-follow real directory."
    }
    return ,$handle
  } catch {
    $handle.Dispose()
    throw
  }
}

function Assert-SameNoFollowDirectoryIdentity(
  [string]$ActualPath,
  [string]$ExpectedPath,
  [string]$Label
) {
  $actualHandle = Open-NoFollowRealDirectory $ActualPath "$Label reported directory"
  try {
    $expectedHandle = Open-NoFollowRealDirectory $ExpectedPath "$Label expected directory"
    try {
      # Both restrictive no-follow handles stay open for the complete comparison.
      # Path spelling (including Windows' \\?\ form) is never treated as ownership.
      $actualBefore = Get-OpenDirectoryIdentity $actualHandle
      $expectedBefore = Get-OpenDirectoryIdentity $expectedHandle
      if ($actualBefore.volume -ne $expectedBefore.volume -or
          $actualBefore.index -ne $expectedBefore.index) {
        throw "$Label does not refer to the exact same directory object."
      }
      $actualAfter = Get-OpenDirectoryIdentity $actualHandle
      $expectedAfter = Get-OpenDirectoryIdentity $expectedHandle
      if ($actualBefore.attributes -ne $actualAfter.attributes -or
          $actualBefore.volume -ne $actualAfter.volume -or
          $actualBefore.index -ne $actualAfter.index -or
          $expectedBefore.attributes -ne $expectedAfter.attributes -or
          $expectedBefore.volume -ne $expectedAfter.volume -or
          $expectedBefore.index -ne $expectedAfter.index) {
        throw "$Label directory identity changed while both proof handles were held."
      }
    } finally {
      $expectedHandle.Dispose()
    }
  } finally {
    $actualHandle.Dispose()
  }
}

function Assert-SingleLinkFile([string]$Path, [string]$Label, [uint64]$MaximumBytes = [uint64]::MaxValue) {
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

function Get-NoFollowWindowsSystemExecutableProof(
  [string]$Path,
  [string]$ExpectedDirectory,
  [string]$ExpectedName,
  [string]$Label
) {
  Assert-ExactChildPath $ExpectedDirectory $Path $ExpectedName $Label | Out-Null
  $stream = Open-NoFollowWindowsSystemFile $Path $Label
  try {
    $before = Get-OpenFileIdentity $stream
    $digest = [Security.Cryptography.SHA256]::HashData($stream)
    $after = Get-OpenFileIdentity $stream
    if ($before.attributes -ne $after.attributes -or $before.links -ne $after.links -or
        $before.bytes -ne $after.bytes -or $before.volume -ne $after.volume -or
        $before.index -ne $after.index) {
      throw "$Label changed while its exact no-follow handle was hashed."
    }
    $sha256 = [Convert]::ToHexString($digest).ToLowerInvariant()

    # Keep this original no-write/no-delete-sharing handle open throughout the
    # path-based Authenticode/catalog lookup. The System32 name therefore cannot
    # be swapped to a different signed file and restored between the two hashes.
    $signature = Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop
    if ([string]$signature.Status -cne "Valid" -or $null -eq $signature.SignerCertificate) {
      throw "$Label does not have a valid Windows Authenticode or catalog signature."
    }
    $signerSubject = [string]$signature.SignerCertificate.Subject
    if ($signerSubject -cnotmatch '(?i)(?:^|,\s*)O=Microsoft Corporation(?:,|$)') {
      throw "$Label is not signed by Microsoft Corporation."
    }
    $signerThumbprint = ([string]$signature.SignerCertificate.Thumbprint).ToLowerInvariant()
    if ($signerThumbprint -cnotmatch '^[0-9a-f]{40,128}$') {
      throw "$Label returned an invalid signer thumbprint."
    }

    $stream.Position = 0
    $afterSignatureDigest = [Security.Cryptography.SHA256]::HashData($stream)
    $afterSignature = Get-OpenFileIdentity $stream
    if ($before.attributes -ne $afterSignature.attributes -or
        $before.links -ne $afterSignature.links -or
        $before.bytes -ne $afterSignature.bytes -or
        $before.volume -ne $afterSignature.volume -or
        $before.index -ne $afterSignature.index -or
        $sha256 -cne [Convert]::ToHexString($afterSignatureDigest).ToLowerInvariant()) {
      throw "$Label original Windows-system handle changed while its signature was verified."
    }

    return [PSCustomObject]@{
      FullName = [IO.Path]::GetFullPath($Path)
      Length = [int64]$before.bytes
      Sha256 = $sha256
      Volume = [uint32]$before.volume
      FileIndex = [uint64]$before.index
      Links = [uint32]$before.links
      TrustPolicy = "windows_system32_microsoft_authenticode_v1"
      SignerThumbprint = $signerThumbprint
    }
  } finally {
    $stream.Dispose()
  }
}

function Get-LowerSha256([string]$Path, [uint64]$MaximumBytes = 8GB) {
  return (Get-NoFollowFileSha256Proof $Path "SHA-256 input" $MaximumBytes).Sha256
}

function Invoke-ExactProcess(
  [string]$FileName,
  [string[]]$Arguments,
  [int]$TimeoutMilliseconds,
  [string]$Label,
  [bool]$CaptureOutput = $false,
  [Collections.Generic.Dictionary[string,string]]$Environment = $null,
  [object]$ExpectedExecutableProof = $null,
  [object]$ExpectedSystemExecutableProof = $null
) {
  if ($TimeoutMilliseconds -lt 1000 -or $TimeoutMilliseconds -gt 1800000) {
    throw "$Label timeout is outside its fixed bound."
  }
  $startInfo = [Diagnostics.ProcessStartInfo]::new()
  $startInfo.FileName = $FileName
  $startInfo.UseShellExecute = $false
  $startInfo.CreateNoWindow = $true
  $startInfo.RedirectStandardOutput = $CaptureOutput
  $startInfo.RedirectStandardError = $CaptureOutput
  foreach ($argument in $Arguments) { $startInfo.ArgumentList.Add($argument) }
  if ($null -ne $Environment) {
    $startInfo.Environment.Clear()
    foreach ($entry in $Environment.GetEnumerator()) { $startInfo.Environment[$entry.Key] = $entry.Value }
  }
  $process = [Diagnostics.Process]::new()
  $process.StartInfo = $startInfo
  try {
    if ($null -ne $ExpectedExecutableProof -and $null -ne $ExpectedSystemExecutableProof) {
      throw "$Label cannot use both product-file and Windows-system executable proofs."
    }
    $isTrustedWindowsSystemExecutable = $null -ne $ExpectedSystemExecutableProof
    $proof = if ($isTrustedWindowsSystemExecutable) { $ExpectedSystemExecutableProof } else { $ExpectedExecutableProof }
    $executionGuard = if ($isTrustedWindowsSystemExecutable) {
      Open-NoFollowWindowsSystemFile $FileName "$Label executable" (512 * 1024 * 1024)
    } else {
      Open-NoFollowSingleLinkFile $FileName "$Label executable" (512 * 1024 * 1024)
    }
    try {
      if ($null -ne $proof) {
        foreach ($requiredProofField in @("FullName", "Length", "Sha256", "Volume", "FileIndex")) {
          if ($null -eq $proof.PSObject.Properties[$requiredProofField]) {
            throw "$Label has an incomplete expected executable proof."
          }
        }
        if (-not [String]::Equals(
            [IO.Path]::GetFullPath($FileName),
            [string]$proof.FullName,
            [StringComparison]::OrdinalIgnoreCase
          ) -or [int64]$proof.Length -lt 1 -or
          [string]$proof.Sha256 -cnotmatch '^[0-9a-f]{64}$') {
          throw "$Label has a malformed expected executable proof."
        }
        if ($isTrustedWindowsSystemExecutable) {
          foreach ($requiredSystemProofField in @("Links", "TrustPolicy", "SignerThumbprint")) {
            if ($null -eq $proof.PSObject.Properties[$requiredSystemProofField]) {
              throw "$Label has an incomplete Windows-system executable proof."
            }
          }
          if ([uint32]$proof.Links -lt 1 -or
              [string]$proof.TrustPolicy -cne "windows_system32_microsoft_authenticode_v1" -or
              [string]$proof.SignerThumbprint -cnotmatch '^[0-9a-f]{40,128}$') {
            throw "$Label has a malformed Windows-system executable proof."
          }
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
        if ([uint64]$beforeExecution.bytes -ne [uint64]$proof.Length -or
            [uint32]$beforeExecution.volume -ne [uint32]$proof.Volume -or
            [uint64]$beforeExecution.index -ne [uint64]$proof.FileIndex -or
            ($isTrustedWindowsSystemExecutable -and [uint32]$beforeExecution.links -ne [uint32]$proof.Links) -or
            $executionSha256 -cne [string]$proof.Sha256) {
          throw "$Label executable is not the exact previously verified installer."
        }
        $executionGuard.Position = 0
      }
      $started = $process.Start()
      if ($null -ne $proof) {
        $afterStart = Get-OpenFileIdentity $executionGuard
        if ([uint64]$afterStart.bytes -ne [uint64]$proof.Length -or
            [uint32]$afterStart.volume -ne [uint32]$proof.Volume -or
            [uint64]$afterStart.index -ne [uint64]$proof.FileIndex -or
            ($isTrustedWindowsSystemExecutable -and [uint32]$afterStart.links -ne [uint32]$proof.Links)) {
          throw "$Label executable changed while the verified process was started."
        }
      }
    } finally {
      $executionGuard.Dispose()
    }
    if (-not $started) { throw "$Label did not start." }
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
      $drain = [Threading.Tasks.Task]::WhenAll([Threading.Tasks.Task[]]@($stdoutTask, $stderrTask))
      if (-not $drain.Wait(5000) -or -not $drain.IsCompletedSuccessfully) {
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
      $bounded = ($stdout + " " + $stderr).Replace("`r", " ").Replace("`n", " ")
      if ($bounded.Length -gt 4096) { $bounded = $bounded.Substring(0, 4096) + " (truncated)" }
      throw "$Label failed with status $($process.ExitCode): $bounded"
    }
    return [ordered]@{ stdout = $stdout; stderr = $stderr; exitCode = $process.ExitCode }
  } finally {
    $process.Dispose()
  }
}

function Invoke-CliJson([string]$Cli, [string[]]$Arguments, [int]$TimeoutMilliseconds, [string]$Label) {
  $result = Invoke-ExactProcess $Cli $Arguments $TimeoutMilliseconds $Label $true
  try { return $result.stdout | ConvertFrom-Json -DateKind String }
  catch { throw "$Label did not emit one valid JSON document." }
}

function Get-CliVersion([string]$Cli, [string]$Label) {
  $result = Invoke-ExactProcess $Cli @("--version") 30000 "$Label version probe" $true
  $match = [Text.RegularExpressions.Regex]::Match(
    $result.stdout.Trim(),
    "^ai-security-scanner ([0-9]+[.][0-9]+[.][0-9]+)$",
    [Text.RegularExpressions.RegexOptions]::CultureInvariant
  )
  if (-not $match.Success) { throw "$Label returned an unexpected version string." }
  return $match.Groups[1].Value
}

function Find-OneInstalledFile([string]$InstallDirectory, [string]$Name) {
  $matches = @(
    Get-ChildItem -LiteralPath $InstallDirectory -Filter $Name -File -Recurse -Force |
      Where-Object { ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0 }
  )
  if ($matches.Count -ne 1) { throw "Expected one installed $Name, found $($matches.Count)." }
  $path = [IO.Path]::GetFullPath($matches[0].FullName)
  $prefix = [IO.Path]::GetFullPath($InstallDirectory) + [IO.Path]::DirectorySeparatorChar
  if (-not $path.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
    throw "Installed $Name escaped the exact install directory."
  }
  Assert-SingleLinkFile $path "Installed $Name" | Out-Null
  return $path
}

function Get-OptionalRegistryString([object]$Properties, [string]$Name) {
  $property = $Properties.PSObject.Properties[$Name]
  if ($null -eq $property -or $null -eq $property.Value) { return "" }
  return [string]$property.Value
}

function Assert-ExactJsonProperties([object]$Value, [string[]]$ExpectedNames, [string]$Label) {
  if ($null -eq $Value) { throw "$Label is not a JSON object." }
  [string[]]$actualNames = @($Value.PSObject.Properties.Name)
  if ($actualNames.Count -ne $ExpectedNames.Count) {
    throw "$Label has an unexpected field count."
  }
  foreach ($expectedName in $ExpectedNames) {
    if (-not ($actualNames -ccontains $expectedName)) {
      throw "$Label is missing exact field $expectedName."
    }
  }
}

function Get-ComparableWindowsPath([string]$Path, [string]$Label) {
  if ([String]::IsNullOrWhiteSpace($Path) -or -not [IO.Path]::IsPathFullyQualified($Path)) {
    throw "$Label is not an absolute Windows path."
  }
  $full = [IO.Path]::GetFullPath($Path)
  if ($full.StartsWith("\\?\UNC\", [StringComparison]::OrdinalIgnoreCase)) {
    $full = "\\" + $full.Substring(8)
  } elseif ($full.StartsWith("\\?\", [StringComparison]::OrdinalIgnoreCase)) {
    $full = $full.Substring(4)
  }
  return $full.TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar)
}

function Assert-SameWindowsPath([string]$Actual, [string]$Expected, [string]$Label) {
  $actualPath = Get-ComparableWindowsPath $Actual "$Label reported path"
  $expectedPath = Get-ComparableWindowsPath $Expected "$Label expected path"
  if (-not [String]::Equals($actualPath, $expectedPath, [StringComparison]::OrdinalIgnoreCase)) {
    throw "$Label is not bound to its exact qualification path."
  }
}

function Get-ProductRegistryEntries {
  $root = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall"
  if (-not (Test-Path -LiteralPath $root -PathType Container)) { return @() }
  $children = @(Get-ChildItem -LiteralPath $root -ErrorAction Stop)
  if ($children.Count -gt 512) { throw "Current-user uninstall registry exceeded its bound." }
  return @(
    $children | ForEach-Object {
      $properties = Get-ItemProperty -LiteralPath $_.PSPath -ErrorAction Stop
      if ((Get-OptionalRegistryString $properties "DisplayName") -ceq "ai-security-scanner") {
        [PSCustomObject]@{
          KeyPath = $_.PSPath
          KeyName = $_.PSChildName
          DisplayName = Get-OptionalRegistryString $properties "DisplayName"
          Publisher = Get-OptionalRegistryString $properties "Publisher"
          DisplayVersion = Get-OptionalRegistryString $properties "DisplayVersion"
          InstallLocation = Get-OptionalRegistryString $properties "InstallLocation"
          UninstallString = Get-OptionalRegistryString $properties "UninstallString"
          MainBinaryName = Get-OptionalRegistryString $properties "MainBinaryName"
          InstallTransitionPresent = ($null -ne $properties.PSObject.Properties["InstallTransition"])
          InstallTransition = Get-OptionalRegistryString $properties "InstallTransition"
        }
      }
    }
  )
}

function Get-ExactProductRegistry([string]$ExpectedVersion, [string]$InstallDirectory) {
  $entries = @(Get-ProductRegistryEntries)
  if ($entries.Count -ne 1) { throw "Expected one ai-security-scanner HKCU registration, found $($entries.Count)." }
  $entry = $entries[0]
  $quotedInstall = '"' + [IO.Path]::GetFullPath($InstallDirectory) + '"'
  $quotedUninstall = '"' + [IO.Path]::GetFullPath((Join-Path $InstallDirectory "uninstall.exe")) + '"'
  if ($entry.KeyName -cne "ai-security-scanner" -or
      $entry.DisplayName -cne "ai-security-scanner" -or
      $entry.Publisher -cne "ai-security-scanner contributors" -or
      $entry.DisplayVersion -cne $ExpectedVersion -or
      $entry.MainBinaryName -cne "ai-security-scanner.exe" -or
      -not [String]::Equals($entry.InstallLocation, $quotedInstall, [StringComparison]::OrdinalIgnoreCase) -or
      -not [String]::Equals($entry.UninstallString, $quotedUninstall, [StringComparison]::OrdinalIgnoreCase)) {
    throw "The HKCU product registration is not the exact bounded NSIS identity."
  }
  return $entry
}

function Resolve-RealDirectory([string]$Path, [string]$Label) {
  $resolved = (Resolve-Path -LiteralPath $Path -ErrorAction Stop).Path
  Assert-RealDirectory $resolved $Label | Out-Null
  return [IO.Path]::GetFullPath($resolved)
}

function Get-WslRegistrations {
  $root = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Lxss"
  if (-not (Test-Path -LiteralPath $root -PathType Container)) { return @() }
  $children = @(Get-ChildItem -LiteralPath $root -ErrorAction Stop)
  if ($children.Count -gt 256) { throw "WSL registration registry exceeded its qualification bound." }
  return @(
    $children | ForEach-Object {
      $properties = Get-ItemProperty -LiteralPath $_.PSPath -ErrorAction Stop
      $name = Get-OptionalRegistryString $properties "DistributionName"
      $basePath = Get-OptionalRegistryString $properties "BasePath"
      if (-not [String]::IsNullOrWhiteSpace($name)) {
        [PSCustomObject]@{ Name = $name; BasePath = $basePath; KeyPath = $_.PSPath }
      }
    }
  )
}

function Get-ExactWslRegistration([string]$Name, [string]$ExpectedBasePath) {
  $matches = @(Get-WslRegistrations | Where-Object {
    [String]::Equals($_.Name, $Name, [StringComparison]::Ordinal)
  })
  if ($matches.Count -ne 1) { throw "Expected one exact WSL registration for $Name, found $($matches.Count)." }
  $registeredBasePath = Get-BoundedAbsoluteWindowsPath $matches[0].BasePath (
    "Exact WSL registration BasePath"
  )
  $boundedExpectedBasePath = Get-BoundedAbsoluteWindowsPath $ExpectedBasePath (
    "Expected managed WSL BasePath"
  )
  Assert-SameNoFollowDirectoryIdentity $registeredBasePath $boundedExpectedBasePath (
    "Exact WSL registration for $Name"
  )
  return $matches[0]
}

function Assert-NoFollowDirectoryIdentityRegression([string]$Parent) {
  $fixtureName = "directory-identity-regression"
  $fixtureRoot = Assert-ExactChildPath $Parent (Join-Path $Parent $fixtureName) $fixtureName (
    "Directory identity regression fixture"
  )
  if (Test-Path -LiteralPath $fixtureRoot) {
    throw "Directory identity regression fixture already exists."
  }
  New-Item -ItemType Directory -Path $fixtureRoot | Out-Null
  try {
    $sameDirectory = Assert-ExactChildPath $fixtureRoot (
      Join-Path $fixtureRoot "same"
    ) "same" "Same-directory identity fixture"
    $differentDirectory = Assert-ExactChildPath $fixtureRoot (
      Join-Path $fixtureRoot "different"
    ) "different" "Different-directory identity fixture"
    New-Item -ItemType Directory -Path $sameDirectory | Out-Null
    New-Item -ItemType Directory -Path $differentDirectory | Out-Null

    $extendedSameDirectory = Get-VerbatimWindowsPath $sameDirectory (
      "Extended-prefix same-directory identity fixture"
    )
    if ([String]::Equals($sameDirectory, $extendedSameDirectory, [StringComparison]::Ordinal)) {
      throw "Directory identity regression did not exercise two Windows path spellings."
    }
    Assert-SameNoFollowDirectoryIdentity $sameDirectory $extendedSameDirectory (
      "Same-directory extended-prefix regression"
    )

    $differentRejected = $false
    try {
      Assert-SameNoFollowDirectoryIdentity $sameDirectory $differentDirectory (
        "Different-directory regression"
      )
    } catch {
      if ($_.Exception.Message -cne (
          "Different-directory regression does not refer to the exact same directory object."
        )) { throw }
      $differentRejected = $true
    }
    if (-not $differentRejected) {
      throw "Directory identity comparison accepted two different directory objects."
    }
  } finally {
    Remove-ExactTree $fixtureRoot $Parent $fixtureName "Directory identity regression fixture"
  }
}

function Get-PreservedDataSnapshot([string]$Root) {
  Assert-RealDirectory $Root "Private application data root" | Out-Null
  $rootPath = [IO.Path]::GetFullPath($Root)
  $files = [Collections.Generic.List[object]]::new()
  [int64]$totalBytes = 0
  $items = @(Get-ChildItem -LiteralPath $rootPath -Force -Recurse)
  if ($items.Count -gt $maximumSnapshotFiles * 4) { throw "Preserved data tree exceeded its entry bound." }
  foreach ($item in $items) {
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
      throw "Private application data contains a reparse-point entry."
    }
    $relative = [IO.Path]::GetRelativePath($rootPath, $item.FullName).Replace('\', '/')
    # Runtime maintenance legitimately leaves this one empty, root-level
    # process-coordination file behind. Prove its exact empty regular-file shape
    # before excluding it; every other empty file remains fail-closed through
    # Get-NoFollowFileSha256Proof below.
    if (-not $item.PSIsContainer -and $relative -ceq $processLeaseRelativePath) {
      Assert-ExactEmptyProcessLeaseFile $item.FullName "Root process lease"
      continue
    }
    if ($relative -eq "managed-runtime" -or $relative.StartsWith("managed-runtime/", [StringComparison]::Ordinal)) {
      continue
    }
    if ($item.PSIsContainer) { continue }
    if ($files.Count -eq $maximumSnapshotFiles) { throw "Preserved data exceeded its file-count bound." }
    $fileProof = Get-NoFollowFileSha256Proof $item.FullName "Preserved data file" $maximumSnapshotBytes
    $totalBytes += [int64]$fileProof.Length
    if ($totalBytes -gt $maximumSnapshotBytes) { throw "Preserved data exceeded its byte bound." }
    $files.Add([ordered]@{
      path = $relative
      bytes = [int64]$fileProof.Length
      sha256 = [string]$fileProof.Sha256
    })
  }
  $ordered = @($files | Sort-Object { $_.path })
  $encoded = ConvertTo-Json -InputObject $ordered -Compress -Depth 5
  $digest = [Convert]::ToHexString(
    [Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($encoded))
  ).ToLowerInvariant()
  return [ordered]@{ fileCount = $ordered.Count; totalBytes = $totalBytes; digest = $digest }
}

function Assert-PreservedDataSnapshotHousekeepingRegression([string]$Parent) {
  $fixtureName = "preserved-data-housekeeping-regression"
  $fixtureRoot = Assert-ExactChildPath $Parent (Join-Path $Parent $fixtureName) $fixtureName (
    "Preserved-data housekeeping regression fixture"
  )
  if (Test-Path -LiteralPath $fixtureRoot) {
    throw "Preserved-data housekeeping regression fixture already exists."
  }
  New-Item -ItemType Directory -Path $fixtureRoot | Out-Null
  try {
    [byte[]]$payloadBytes = [Text.Encoding]::UTF8.GetBytes("preserved-user-data")
    [IO.File]::WriteAllBytes((Join-Path $fixtureRoot "user-data.bin"), $payloadBytes)
    [IO.File]::WriteAllBytes((Join-Path $fixtureRoot $processLeaseRelativePath), [byte[]]::new(0))

    $snapshot = Get-PreservedDataSnapshot $fixtureRoot
    if ($snapshot.fileCount -ne 1 -or $snapshot.totalBytes -ne $payloadBytes.Length) {
      throw "Preserved-data snapshot did not exclude only the exact root process lease."
    }

    $nestedDirectory = Assert-ExactChildPath $fixtureRoot (
      Join-Path $fixtureRoot "nested"
    ) "nested" "Nested process-lease regression directory"
    New-Item -ItemType Directory -Path $nestedDirectory | Out-Null
    [IO.File]::WriteAllBytes(
      (Join-Path $nestedDirectory $processLeaseRelativePath),
      [byte[]]::new(0)
    )
    $nestedLeaseRejected = $false
    try {
      Get-PreservedDataSnapshot $fixtureRoot | Out-Null
    } catch {
      if ($_.Exception.Message -cne "Preserved data file is not one bounded no-follow single-link regular file.") {
        throw
      }
      $nestedLeaseRejected = $true
    }
    if (-not $nestedLeaseRejected) {
      throw "Preserved-data snapshot ignored a nested process-lease-shaped file."
    }
  } finally {
    Remove-ExactTree $fixtureRoot $Parent $fixtureName "Preserved-data housekeeping regression fixture"
  }
}

function Read-BoundedUtf8File(
  [string]$Path,
  [string]$Label,
  [uint64]$MaximumBytes = 64 * 1024
) {
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

function Read-BoundedJsonFile(
  [string]$Path,
  [string]$Label,
  [uint64]$MaximumBytes = 64 * 1024
) {
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

function Remove-ExactTree([string]$Path, [string]$Parent, [string]$ExpectedName, [string]$Label) {
  Assert-ExactChildPath $Parent $Path $ExpectedName $Label | Out-Null
  if (Test-Path -LiteralPath $Path) {
    Assert-RealDirectory $Path $Label | Out-Null
    Remove-Item -LiteralPath $Path -Recurse -Force
  }
  if (Test-Path -LiteralPath $Path) { throw "$Label remains after exact cleanup." }
}

function Download-PinnedPriorInstaller([string]$Destination) {
  $handler = [Net.Http.HttpClientHandler]::new()
  $handler.AllowAutoRedirect = $true
  $handler.MaxAutomaticRedirections = 5
  $handler.UseCookies = $false
  $client = [Net.Http.HttpClient]::new($handler)
  $client.Timeout = [TimeSpan]::FromMinutes(5)
  try {
    $response = $client.GetAsync($priorInstallerUrl, [Net.Http.HttpCompletionOption]::ResponseHeadersRead).Result
    try {
      $response.EnsureSuccessStatusCode() | Out-Null
      if ($null -ne $response.Content.Headers.ContentLength -and
          ($response.Content.Headers.ContentLength -ne $priorInstallerBytes -or
           $response.Content.Headers.ContentLength -gt $maximumDownloadBytes)) {
        throw "Pinned v0.1.7 installer Content-Length changed."
      }
      $input = $response.Content.ReadAsStream()
      $output = [IO.FileStream]::new($Destination, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
      try {
        [byte[]]$buffer = [byte[]]::new(64 * 1024)
        [int64]$written = 0
        while (($read = $input.Read($buffer, 0, $buffer.Length)) -gt 0) {
          $written += $read
          if ($written -gt $maximumDownloadBytes) { throw "Pinned v0.1.7 installer exceeded its download bound." }
          $output.Write($buffer, 0, $read)
        }
        $output.Flush($true)
      } finally {
        $output.Dispose()
        $input.Dispose()
      }
    } finally { $response.Dispose() }
  } finally {
    $client.Dispose()
    $handler.Dispose()
  }
  $proof = Get-NoFollowFileSha256Proof $Destination "Pinned v0.1.7 installer" $maximumDownloadBytes
  if ($proof.Length -ne $priorInstallerBytes -or $proof.Sha256 -cne $priorInstallerSha256) {
    throw "Downloaded v0.1.7 installer differs from its immutable pin."
  }
  return $proof
}

function Get-TrustedWslExecutable {
  $buffer = [Text.StringBuilder]::new(32768)
  $length = [GhostQualificationNativeMethods]::GetSystemWindowsDirectoryW($buffer, [uint32]$buffer.Capacity)
  if ($length -eq 0 -or $length -ge $buffer.Capacity) { throw "Could not resolve OS-trusted Windows directory." }
  $windows = Resolve-RealDirectory $buffer.ToString() "OS-trusted Windows directory"
  $system32 = Resolve-RealDirectory (Join-Path $windows "System32") "OS-trusted System32"
  $wsl = Join-Path $system32 "wsl.exe"
  $proof = Get-NoFollowWindowsSystemExecutableProof $wsl $system32 "wsl.exe" "OS-trusted wsl.exe"
  return [ordered]@{ executable = $wsl; windows = $windows; system32 = $system32; proof = $proof }
}

function Unregister-ProvenExactWsl([object]$TrustedWsl, [string]$Name) {
  $environment = [Collections.Generic.Dictionary[string,string]]::new([StringComparer]::OrdinalIgnoreCase)
  $environment["SystemRoot"] = $TrustedWsl.windows
  $environment["WINDIR"] = $TrustedWsl.windows
  $environment["PATH"] = $TrustedWsl.system32
  $environment["NoDefaultCurrentDirectoryInExePath"] = "1"
  Invoke-ExactProcess $TrustedWsl.executable @("--unregister", $Name) 90000 "Exact managed WSL cleanup" $true $environment -ExpectedSystemExecutableProof $TrustedWsl.proof | Out-Null
}

$artifactRoot = (Resolve-Path -LiteralPath $ArtifactDirectory).Path
$runnerTemp = [IO.Path]::GetFullPath($env:RUNNER_TEMP)
Assert-RealDirectory $runnerTemp "RUNNER_TEMP" | Out-Null
$workRoot = Assert-ExactChildPath $runnerTemp $WorkDirectory "ai-security-scanner-nsis-ghost-recovery-evidence" "Ghost qualification work directory"
New-Item -ItemType Directory -Path $workRoot -Force | Out-Null
Assert-RealDirectory $workRoot "Ghost qualification work directory" | Out-Null
Assert-NoFollowDirectoryIdentityRegression $workRoot
Assert-PreservedDataSnapshotHousekeepingRegression $workRoot
$localApplicationData = [IO.Path]::GetFullPath([Environment]::GetFolderPath([Environment+SpecialFolder]::LocalApplicationData))
Assert-RealDirectory $localApplicationData "OS-resolved LocalApplicationData" | Out-Null
$installDirectory = Assert-ExactChildPath $localApplicationData (Join-Path $localApplicationData "ai-security-scanner") "ai-security-scanner" "Default NSIS install directory"
$dataDirectory = Assert-ExactChildPath $localApplicationData (Join-Path $localApplicationData "dev.teddashh.ai-security-scanner") "dev.teddashh.ai-security-scanner" "Default private data directory"
$priorInstallerPath = Assert-ExactChildPath $workRoot (Join-Path $workRoot $priorInstallerName) $priorInstallerName "Pinned prior installer"
$oldProviderHome = Join-Path $dataDirectory "managed-runtime\provider-home\$priorProviderNamespace"
$oldVersionRoot = Join-Path $dataDirectory "managed-runtime\versions"
$oldVersionDirectory = Join-Path $oldVersionRoot $oldVersionDirectoryName

foreach ($path in @($installDirectory, $dataDirectory, $priorInstallerPath)) {
  if (Test-Path -LiteralPath $path) { throw "Ghost qualification requires a fresh exact namespace: $path" }
}
if (@(Get-ProductRegistryEntries).Count -ne 0) { throw "Ghost qualification requires no existing product registration." }

$installerManifest = Read-BoundedJsonFile (Join-Path $artifactRoot "installers-windows-x86_64.json") "Candidate installer manifest" (1024 * 1024)
$candidateRecords = @($installerManifest.installers | Where-Object { $_.bundleType -ceq "nsis" })
if ($installerManifest.version -cne $CurrentVersion -or $candidateRecords.Count -ne 1 -or
    [IO.Path]::GetFileName([string]$candidateRecords[0].file) -cne [string]$candidateRecords[0].file) {
  throw "Candidate artifact does not contain one flat NSIS installer for 0.1.8."
}
$candidateInstallerPath = (Resolve-Path -LiteralPath (Join-Path $artifactRoot $candidateRecords[0].file)).Path
if (-not [String]::Equals([IO.Path]::GetDirectoryName($candidateInstallerPath), $artifactRoot, [StringComparison]::OrdinalIgnoreCase)) {
  throw "Candidate NSIS installer escaped its artifact directory."
}
$candidateInstaller = Get-NoFollowFileSha256Proof $candidateInstallerPath "Candidate NSIS installer" (256 * 1024 * 1024)
$candidateInstallerSha256 = [string]$candidateInstaller.Sha256
if ($candidateInstaller.Length -ne [int64]$candidateRecords[0].bytes -or
    $candidateInstallerSha256 -cne [string]$candidateRecords[0].sha256) {
  throw "Candidate NSIS installer differs from its release manifest."
}

$candidateRuntimeEvidencePath = Join-Path $artifactRoot "managed-runtime-windows-x86_64.manifest.json"
$candidateRuntimeEvidence = Read-BoundedJsonFile $candidateRuntimeEvidencePath "Candidate managed-runtime manifest" (1024 * 1024)
$candidateRuntimeManifestSha256 = Get-LowerSha256 $candidateRuntimeEvidencePath (1024 * 1024)
if ($candidateRuntimeManifestSha256 -cne $candidateRuntimeManifestExpectedSha256) {
  throw "Candidate managed-runtime evidence differs from the reviewed v0.1.8 Windows identity."
}
$candidateProviderNamespace = $candidateRuntimeManifestSha256.Substring(0, 16)
$candidateTargets = @($candidateRuntimeEvidence.targets | Where-Object {
  $_.operating_system -ceq "windows" -and $_.architecture -ceq "x86_64" -and $_.provider -ceq "wsl"
})
if ($candidateRuntimeEvidence.schema_version -cne "3" -or
    $candidateRuntimeEvidence.management_contract_revision -cne "2026-08-29.1" -or
    $candidateRuntimeEvidence.bundle_id -cne "podman-machine" -or
    $candidateRuntimeEvidence.runtime_version -cne "5.8.2" -or $candidateTargets.Count -ne 1) {
  throw "Candidate managed-runtime evidence has no exact Windows WSL identity."
}
$candidateMachineImageSha256 = [string]$candidateTargets[0].machine_image.sha256
$candidateProviderHome = Join-Path $dataDirectory "managed-runtime\provider-home\$candidateProviderNamespace"
$candidateVersionDirectory = Join-Path $dataDirectory "managed-runtime\versions\podman-machine-5.8.2-$candidateProviderNamespace"
$trustedWsl = Get-TrustedWslExecutable

$activeCli = $null
$activeUninstaller = $null
$primaryFailure = $null
$cleanupFailures = [Collections.Generic.List[string]]::new()
$observations = $null
$cleanupComplete = $false

try {
  $priorInstallerProof = Download-PinnedPriorInstaller $priorInstallerPath
  Invoke-ExactProcess $priorInstallerPath @("/S") 180000 "Pinned v0.1.7 default NSIS installation" -ExpectedExecutableProof $priorInstallerProof | Out-Null
  Assert-RealDirectory $installDirectory "v0.1.7 default install directory" | Out-Null
  $oldDesktop = Find-OneInstalledFile $installDirectory "ai-security-scanner.exe"
  $oldCli = Find-OneInstalledFile $installDirectory "ai-security-scanner-cli.exe"
  $oldUninstaller = Find-OneInstalledFile $installDirectory "uninstall.exe"
  $activeCli = $oldCli
  $activeUninstaller = $oldUninstaller
  $priorCliVersion = Get-CliVersion $oldCli "Pinned v0.1.7 CLI"
  if ($priorCliVersion -cne $priorVersion) { throw "Pinned installer did not install CLI v0.1.7." }
  $oldRegistry = Get-ExactProductRegistry $priorVersion $installDirectory
  if ($oldRegistry.InstallTransitionPresent -or
      -not [String]::IsNullOrEmpty($oldRegistry.InstallTransition)) {
    throw "v0.1.7 fixture unexpectedly started with a migration receipt."
  }

  $installedOldRuntimeManifests = @(
    Get-ChildItem -LiteralPath $installDirectory -Filter "manifest.json" -File -Recurse -Force |
      Where-Object { $_.FullName -match '(?i)[\\/]managed-runtime[\\/]manifest\.json$' }
  )
  if ($installedOldRuntimeManifests.Count -ne 1 -or
      (Get-LowerSha256 $installedOldRuntimeManifests[0].FullName (1024 * 1024)) -cne $priorRuntimeManifestSha256) {
    throw "v0.1.7 installed runtime resource differs from its immutable manifest pin."
  }

  New-Item -ItemType Directory -Path $dataDirectory -Force | Out-Null
  $sentinelPath = Join-Path $dataDirectory "ghost-recovery-data-sentinel.json"
  [IO.File]::WriteAllText(
    $sentinelPath,
    '{"schema":"ai-security-scanner.release-qualification/ghost-recovery-v1","value":"synthetic"}',
    [Text.UTF8Encoding]::new($false)
  )
  $demoCase = Invoke-CliJson $oldCli @("--json", "--data-dir", $dataDirectory, "case", "seed-demo") 120000 "v0.1.7 synthetic case seed"
  if ([string]::IsNullOrWhiteSpace([string]$demoCase.id) -or @($demoCase.scan_runs).Count -lt 1) {
    throw "v0.1.7 CLI did not create an exportable synthetic case."
  }
  $caseId = [string]$demoCase.id
  $runId = [string]$demoCase.scan_runs[0].id
  $exportDirectory = Join-Path $dataDirectory "qualification-exports"
  New-Item -ItemType Directory -Path $exportDirectory -Force | Out-Null
  $beforeBundle = Join-Path $exportDirectory "before-ghost-recovery.case.tar.gz"
  Invoke-CliJson $oldCli @(
    "--json", "--data-dir", $dataDirectory, "export", "create", "--case-id", $caseId,
    "--run-id", $runId, "--format", "case-bundle", "--destination", $beforeBundle
  ) 120000 "v0.1.7 signed synthetic export" | Out-Null
  $beforeVerification = Invoke-CliJson $oldCli @(
    "--json", "--data-dir", $dataDirectory, "export", "verify", "--path", $beforeBundle
  ) 120000 "v0.1.7 signed export verification"
  if ($beforeVerification.valid -ne $true) { throw "v0.1.7 signed export did not verify." }
  $privateSigningKey = Join-Path $dataDirectory "integrity-signing-key"
  Assert-SingleLinkFile $privateSigningKey "Integrity signing key" (64 * 1024) | Out-Null
  $privateSigningKeySha256Before = Get-LowerSha256 $privateSigningKey (64 * 1024)

  $oldInstallStatus = Invoke-CliJson $oldCli @(
    "--json", "--data-dir", $dataDirectory, "runtime", "managed", "install"
  ) 900000 "v0.1.7 managed runtime install"
  $oldStartStatus = Invoke-CliJson $oldCli @(
    "--json", "--data-dir", $dataDirectory, "runtime", "managed", "start"
  ) 1200000 "v0.1.7 managed runtime start"
  if ($oldStartStatus.phase -cne "running" -or $oldStartStatus.available -ne $true -or
      $oldStartStatus.manifest_sha256 -cne $priorRuntimeManifestSha256) {
    throw "v0.1.7 managed runtime did not reach its exact running identity."
  }
  $oldStopStatus = Invoke-CliJson $oldCli @(
    "--json", "--data-dir", $dataDirectory, "runtime", "managed", "stop", "--force"
  ) 300000 "v0.1.7 managed runtime stop"
  if ($oldStopStatus.phase -cne "stopped") { throw "v0.1.7 managed runtime did not stop cleanly." }

  Assert-RealDirectory $oldProviderHome "v0.1.7 provider home" | Out-Null
  $oldIdentityRoot = Join-Path $oldProviderHome "data\containers\podman\machine"
  Assert-SingleLinkFile (Join-Path $oldIdentityRoot "machine") "v0.1.7 managed SSH private key" (16 * 1024) | Out-Null
  Assert-SingleLinkFile (Join-Path $oldIdentityRoot "machine.pub") "v0.1.7 managed SSH public key" (4 * 1024) | Out-Null
  $oldWslBasePath = Join-Path $oldProviderHome "data\containers\podman\machine\wsl\wsldist\$oldMachineName"
  Get-ExactWslRegistration $oldDistributionName $oldWslBasePath | Out-Null

  Assert-RealDirectory $oldVersionDirectory "v0.1.7 installed versions payload" | Out-Null
  $oldInstalledManifest = Join-Path $oldVersionDirectory "manifest.json"
  if ((Get-LowerSha256 $oldInstalledManifest (1024 * 1024)) -cne $priorRuntimeManifestSha256) {
    throw "v0.1.7 versions payload did not carry the immutable N-1 manifest."
  }
  Remove-ExactTree $oldVersionDirectory $oldVersionRoot $oldVersionDirectoryName "Exact v0.1.7 versions payload"
  if (-not (Test-Path -LiteralPath $oldProviderHome -PathType Container)) {
    throw "Fixture setup removed the old provider that must remain for bounded proof."
  }

  Assert-SingleLinkFile $oldDesktop "v0.1.7 desktop selected for ghost fixture" | Out-Null
  Assert-SingleLinkFile $oldUninstaller "v0.1.7 uninstaller selected for ghost fixture" | Out-Null
  Remove-Item -LiteralPath $oldDesktop -Force
  Remove-Item -LiteralPath $oldUninstaller -Force
  $activeUninstaller = $null
  if ((Test-Path -LiteralPath $oldDesktop) -or (Test-Path -LiteralPath $oldUninstaller)) {
    throw "Ghost fixture did not remove exactly the old desktop and uninstaller."
  }
  Get-ExactProductRegistry $priorVersion $installDirectory | Out-Null
  Get-ExactWslRegistration $oldDistributionName $oldWslBasePath | Out-Null
  $beforeInstallerSnapshot = Get-PreservedDataSnapshot $dataDirectory

  Invoke-ExactProcess $candidateInstallerPath @("/S") 180000 "Candidate bounded ghost NSIS migration" -ExpectedExecutableProof $candidateInstaller | Out-Null
  $candidateDesktop = Find-OneInstalledFile $installDirectory "ai-security-scanner.exe"
  $candidateCli = Find-OneInstalledFile $installDirectory "ai-security-scanner-cli.exe"
  $candidateUninstaller = Find-OneInstalledFile $installDirectory "uninstall.exe"
  $activeCli = $candidateCli
  $activeUninstaller = $candidateUninstaller
  $candidateCliVersion = Get-CliVersion $candidateCli "Candidate CLI"
  if ($candidateCliVersion -cne $CurrentVersion) { throw "Ghost migration did not install candidate CLI $CurrentVersion." }
  $candidateRegistry = Get-ExactProductRegistry $CurrentVersion $installDirectory
  if (-not $candidateRegistry.InstallTransitionPresent -or
      $candidateRegistry.InstallTransition -cne "recovered-ghost-v0.1.7") {
    throw "Candidate installer did not emit the bounded ghost migration receipt."
  }
  Invoke-ExactProcess $candidateInstallerPath @("/S") 180000 "Candidate same-version silent reinstall before ghost recovery" -ExpectedExecutableProof $candidateInstaller | Out-Null
  $candidateDesktop = Find-OneInstalledFile $installDirectory "ai-security-scanner.exe"
  $candidateCli = Find-OneInstalledFile $installDirectory "ai-security-scanner-cli.exe"
  $candidateUninstaller = Find-OneInstalledFile $installDirectory "uninstall.exe"
  $activeCli = $candidateCli
  $activeUninstaller = $candidateUninstaller
  if ((Get-CliVersion $candidateCli "Same-version reinstalled candidate CLI") -cne $CurrentVersion) {
    throw "Same-version silent reinstall changed the ghost candidate CLI version."
  }
  $candidateRegistry = Get-ExactProductRegistry $CurrentVersion $installDirectory
  if (-not $candidateRegistry.InstallTransitionPresent -or
      $candidateRegistry.InstallTransition -cne "recovered-ghost-v0.1.7") {
    throw "Same-version silent reinstall erased the bounded ghost migration receipt."
  }
  $installerTransitionReceipt = [string]$candidateRegistry.InstallTransition
  $installedCandidateRuntimeManifests = @(
    Get-ChildItem -LiteralPath $installDirectory -Filter "manifest.json" -File -Recurse -Force |
      Where-Object { $_.FullName -match '(?i)[\\/]managed-runtime[\\/]manifest\.json$' }
  )
  if ($installedCandidateRuntimeManifests.Count -ne 1 -or
      (Get-LowerSha256 $installedCandidateRuntimeManifests[0].FullName (1024 * 1024)) -cne $candidateRuntimeManifestSha256) {
    throw "Candidate installed runtime resource differs from released runtime evidence."
  }
  $afterInstallerSnapshot = Get-PreservedDataSnapshot $dataDirectory
  if ($beforeInstallerSnapshot.digest -cne $afterInstallerSnapshot.digest -or
      $beforeInstallerSnapshot.fileCount -ne $afterInstallerSnapshot.fileCount -or
      $beforeInstallerSnapshot.totalBytes -ne $afterInstallerSnapshot.totalBytes) {
    throw "Candidate installer changed private case or signing data during ghost migration."
  }
  $candidateSigningIdentity = Invoke-CliJson $candidateCli @(
    "--json", "--data-dir", $dataDirectory, "export", "identity", "show"
  ) 120000 "Candidate durable export identity adoption"
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
  $privateSigningKeyItem = Assert-OwnerOnlyFullControlFile $privateSigningKey "Managed export signing key" 32
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
      (Get-LowerSha256 $privateSigningKey (64 * 1024)) -cne $privateSigningKeySha256Before) {
    throw "Durable export identity document and anchor do not bind the preserved v0.1.7 key."
  }
  Get-ExactWslRegistration $oldDistributionName $oldWslBasePath | Out-Null

  $recoveryProcess = Invoke-ExactProcess $candidateCli @(
    "--json", "--data-dir", $dataDirectory, "runtime", "managed", "start"
  ) 1200000 "Candidate automatic managed WSL ghost recovery" $true
  if (($recoveryProcess.stdout + $recoveryProcess.stderr).Contains("wsl_distribution_requires_manual_action", [StringComparison]::Ordinal)) {
    throw "Candidate fell back to the manual WSL action during the supported ghost migration."
  }
  try { $recoveredStatus = $recoveryProcess.stdout | ConvertFrom-Json -DateKind String }
  catch { throw "Candidate automatic ghost recovery did not emit valid status JSON." }
  if ($recoveredStatus.phase -cne "running" -or $recoveredStatus.available -ne $true -or
      $recoveredStatus.manifest_sha256 -cne $candidateRuntimeManifestSha256 -or
      $recoveredStatus.machine_image_sha256 -cne $candidateMachineImageSha256) {
    throw "Candidate ghost recovery did not reach the released running runtime identity."
  }
  $postRecoveryRegistry = Get-ExactProductRegistry $CurrentVersion $installDirectory
  if ($postRecoveryRegistry.InstallTransitionPresent -or
      -not [String]::IsNullOrEmpty($postRecoveryRegistry.InstallTransition)) {
    throw "Automatic recovery did not consume the exact HKCU InstallTransition value."
  }
  Assert-RealDirectory $candidateVersionDirectory "Candidate installed runtime version" | Out-Null
  Assert-RealDirectory $candidateProviderHome "Candidate provider home" | Out-Null
  if (Test-Path -LiteralPath $oldProviderHome) { throw "Automatic recovery retained the obsolete provider home." }
  $candidateWslBasePath = Join-Path $candidateProviderHome "data\containers\podman\machine\wsl\wsldist\$oldMachineName"
  Get-ExactWslRegistration $oldDistributionName $candidateWslBasePath | Out-Null

  $pendingRecovery = Join-Path $dataDirectory "managed-runtime\wsl-recovery\pending-$oldMachineName.json"
  if (Test-Path -LiteralPath $pendingRecovery) { throw "Automatic recovery left its pending transaction." }
  $workspaceRoot = Join-Path $dataDirectory "managed-runtime\wsl-recovery-workspaces"
  if ((Test-Path -LiteralPath $workspaceRoot) -and @(Get-ChildItem -LiteralPath $workspaceRoot -Force).Count -ne 0) {
    throw "Automatic recovery left a temporary WSL import workspace."
  }
  $quarantineRegistrations = @(Get-WslRegistrations | Where-Object {
    $_.Name -cmatch '^ai-security-scanner-recovery-[0-9a-f]{32}$'
  })
  if ($quarantineRegistrations.Count -ne 0) { throw "Automatic recovery left a quarantine WSL registration." }

  $recoveryRoot = Join-Path $dataDirectory "managed-runtime\wsl-recovery"
  $consumedProofName = "ghost-migration-consumed-$oldMachineName.json"
  $consumedProofPath = Assert-ExactChildPath $recoveryRoot (
    Join-Path $recoveryRoot $consumedProofName
  ) $consumedProofName "Permanent ghost-migration consumed proof"
  $consumedProofItem = Assert-OwnerOnlyFullControlFile $consumedProofPath (
    "Permanent ghost-migration consumed proof"
  ) (64 * 1024)
  $consumedProofSha256 = Get-LowerSha256 $consumedProofPath (64 * 1024)
  $consumedProof = Read-BoundedJsonFile $consumedProofPath (
    "Permanent ghost-migration consumed proof"
  ) (64 * 1024)
  Assert-ExactJsonProperties $consumedProof @(
    "schema_version",
    "recovery_id",
    "install_transition_receipt",
    "source_provider_manifest_sha256",
    "manifest_sha256",
    "machine_image_sha256",
    "machine_name",
    "distribution_name"
  ) "Permanent ghost-migration consumed proof"
  $recoveryAttempts = @(
    Get-ChildItem -LiteralPath $recoveryRoot -Directory -Force |
      Where-Object { $_.Name -cmatch '^[0-9a-f]{32}$' }
  )
  if ($recoveryAttempts.Count -ne 1) { throw "Expected one durable completed recovery attempt, found $($recoveryAttempts.Count)." }
  $recoveryEntries = @(Get-ChildItem -LiteralPath $recoveryRoot -Force)
  if ($recoveryEntries.Count -ne 2 -or
      @($recoveryEntries | Where-Object { $_.Name -ceq $consumedProofName }).Count -ne 1) {
    throw "Recovery root must contain exactly one retained attempt and its permanent consumed proof."
  }
  $recoveryId = $recoveryAttempts[0].Name
  $attemptRoot = $recoveryAttempts[0].FullName
  $intentPath = Join-Path $attemptRoot "intent.json"
  $intent = Read-BoundedJsonFile $intentPath "Recovery intent"
  $backup = Read-BoundedJsonFile (Join-Path $attemptRoot "backup.json") "Recovery backup receipt"
  $import = Read-BoundedJsonFile (Join-Path $attemptRoot "import.json") "Recovery import receipt"
  $archive = Join-Path $attemptRoot "workspace-recovery.tar"
  $archiveItem = Get-NoFollowFileSha256Proof $archive "Durable WSL recovery archive" (8GB)
  $archiveSha256 = [string]$archiveItem.Sha256
  $parsedRecoveryId = [Guid]::Parse([string]$backup.recovery_id)
  $quarantineName = "ai-security-scanner-recovery-$recoveryId"
  if ($parsedRecoveryId.ToString("N") -cne $recoveryId -or
      $backup.schema_version -cne "ai-security-scanner.managed-wsl-recovery-backup/v1" -or
      $backup.distribution_name -cne $oldDistributionName -or
      $backup.quarantine_distribution_name -cne $quarantineName -or
      [int64]$backup.size_bytes -ne [int64]$archiveItem.Length -or
      [string]$backup.sha256 -cne $archiveSha256) {
    throw "Durable WSL recovery backup receipt is inconsistent."
  }
  if ($import.schema_version -cne "ai-security-scanner.managed-wsl-recovery-import/v1" -or
      ([Guid]::Parse([string]$import.recovery_id)).ToString("N") -cne $recoveryId -or
      $import.quarantine_distribution_name -cne $quarantineName -or
      [int64]$import.archive_size_bytes -ne [int64]$archiveItem.Length -or
      [string]$import.archive_sha256 -cne $archiveSha256 -or
      [string]$backup.sha256 -cne [string]$import.archive_sha256 -or
      [int64]$backup.size_bytes -ne [int64]$import.archive_size_bytes) {
    throw "Durable WSL recovery import receipt is inconsistent with the backup."
  }
  foreach ($reportedArchive in @([string]$backup.recovery_archive, [string]$import.recovery_archive)) {
    if (-not [String]::Equals(
        [IO.Path]::GetFullPath($reportedArchive),
        [IO.Path]::GetFullPath($archive),
        [StringComparison]::OrdinalIgnoreCase
      )) { throw "Recovery receipt is not bound to its exact durable archive." }
  }
  $expectedWorkspace = Join-Path $workspaceRoot $recoveryId
  if (-not [String]::Equals(
      [IO.Path]::GetFullPath([string]$import.quarantine_install_directory),
      [IO.Path]::GetFullPath($expectedWorkspace),
      [StringComparison]::OrdinalIgnoreCase
    )) { throw "Recovery import receipt is not bound to its exact temporary workspace." }
  Assert-ExactJsonProperties $intent @(
    "schema_version",
    "recovery_id",
    "manifest_sha256",
    "machine_image_sha256",
    "ownership_basis",
    "source_provider_manifest_sha256",
    "install_transition_receipt",
    "machine_name",
    "distribution_name",
    "quarantine_distribution_name",
    "registration_base_path",
    "provider_home",
    "attempt_directory",
    "quarantine_install_directory",
    "staging_archive",
    "recovery_archive"
  ) "Recovery intent"
  if ($intent.schema_version -cne "ai-security-scanner.managed-wsl-recovery-intent/v2" -or
      ([Guid]::Parse([string]$intent.recovery_id)).ToString("N") -cne $recoveryId -or
      [string]$intent.manifest_sha256 -cne $candidateRuntimeManifestSha256 -or
      [string]$intent.machine_image_sha256 -cne $candidateMachineImageSha256 -or
      $intent.ownership_basis -cne "bounded_n_minus_one_ghost_migration" -or
      [string]$intent.source_provider_manifest_sha256 -cne $priorRuntimeManifestSha256 -or
      $null -eq $intent.install_transition_receipt -or
      [string]$intent.install_transition_receipt -cne $installerTransitionReceipt -or
      $intent.machine_name -cne $oldMachineName -or
      $intent.distribution_name -cne $oldDistributionName -or
      $intent.quarantine_distribution_name -cne $quarantineName) {
    throw "Recovery intent does not carry the exact bounded N-1 migration proof."
  }
  if ($consumedProof.schema_version -cne "ai-security-scanner.managed-wsl-ghost-migration-consumed/v1" -or
      ([Guid]::Parse([string]$consumedProof.recovery_id)).ToString("N") -cne $recoveryId -or
      [string]$consumedProof.install_transition_receipt -cne $installerTransitionReceipt -or
      [string]$consumedProof.install_transition_receipt -cne [string]$intent.install_transition_receipt -or
      [string]$consumedProof.source_provider_manifest_sha256 -cne $priorRuntimeManifestSha256 -or
      [string]$consumedProof.source_provider_manifest_sha256 -cne [string]$intent.source_provider_manifest_sha256 -or
      [string]$consumedProof.manifest_sha256 -cne $candidateRuntimeManifestSha256 -or
      [string]$consumedProof.manifest_sha256 -cne [string]$intent.manifest_sha256 -or
      [string]$consumedProof.machine_image_sha256 -cne $candidateMachineImageSha256 -or
      [string]$consumedProof.machine_image_sha256 -cne [string]$intent.machine_image_sha256 -or
      [string]$consumedProof.machine_name -cne $oldMachineName -or
      [string]$consumedProof.machine_name -cne [string]$intent.machine_name -or
      [string]$consumedProof.distribution_name -cne $oldDistributionName -or
      [string]$consumedProof.distribution_name -cne [string]$intent.distribution_name) {
    throw "Permanent consumed proof does not carry the exact one-shot N-1 migration identity."
  }
  Assert-SameWindowsPath ([string]$intent.registration_base_path) $oldWslBasePath "Recovery intent registration"
  Assert-SameWindowsPath ([string]$intent.provider_home) $oldProviderHome "Recovery intent source provider"
  Assert-SameWindowsPath ([string]$intent.attempt_directory) $attemptRoot "Recovery intent attempt directory"
  Assert-SameWindowsPath ([string]$intent.quarantine_install_directory) $expectedWorkspace "Recovery intent quarantine workspace"
  Assert-SameWindowsPath ([string]$intent.staging_archive) (Join-Path $attemptRoot "workspace.exporting.tar") "Recovery intent staging archive"
  Assert-SameWindowsPath ([string]$intent.recovery_archive) $archive "Recovery intent durable archive"

  $candidateCase = Invoke-CliJson $candidateCli @(
    "--json", "--data-dir", $dataDirectory, "case", "show", $caseId
  ) 120000 "Recovered candidate synthetic case read"
  if ([string]$candidateCase.id -cne $caseId) { throw "Automatic recovery did not preserve the synthetic case." }
  $afterBundle = Join-Path $exportDirectory "after-ghost-recovery.case.tar.gz"
  Invoke-CliJson $candidateCli @(
    "--json", "--data-dir", $dataDirectory, "export", "create", "--case-id", $caseId,
    "--run-id", $runId, "--format", "case-bundle", "--destination", $afterBundle
  ) 120000 "Recovered candidate signed synthetic export" | Out-Null
  $afterVerification = Invoke-CliJson $candidateCli @(
    "--json", "--data-dir", $dataDirectory, "export", "verify", "--path", $afterBundle
  ) 120000 "Recovered candidate signed export verification"
  if ($afterVerification.valid -ne $true -or
      [string]$afterVerification.signer_key_id -cne [string]$beforeVerification.signer_key_id -or
      [string]$afterVerification.public_key_base64 -cne [string]$beforeVerification.public_key_base64 -or
      (Get-LowerSha256 $privateSigningKey (64 * 1024)) -cne $privateSigningKeySha256Before -or
      -not (Test-Path -LiteralPath $sentinelPath -PathType Leaf) -or
      (Test-Path -LiteralPath $rotationIntentPath)) {
    throw "Automatic recovery did not preserve the case and integrity-signing identity."
  }

  Invoke-CliJson $candidateCli @(
    "--json", "--data-dir", $dataDirectory, "runtime", "managed", "stop", "--force"
  ) 300000 "Recovered managed runtime cleanup stop" | Out-Null
  Invoke-CliJson $candidateCli @(
    "--json", "--data-dir", $dataDirectory, "runtime", "managed", "uninstall", "--force", "--purge-image-cache"
  ) 900000 "Recovered managed runtime cleanup uninstall" | Out-Null
  $postPurgeConsumedProof = Assert-OwnerOnlyFullControlFile $consumedProofPath (
    "Consumed proof retained after managed runtime purge"
  ) (64 * 1024)
  if ($postPurgeConsumedProof.Length -ne $consumedProofItem.Length -or
      (Get-LowerSha256 $consumedProofPath (64 * 1024)) -cne $consumedProofSha256) {
    throw "Managed runtime purge changed or removed the permanent consumed proof."
  }
  $remainingDistribution = @(Get-WslRegistrations | Where-Object {
    [String]::Equals($_.Name, $oldDistributionName, [StringComparison]::Ordinal)
  })
  $remainingQuarantine = @(Get-WslRegistrations | Where-Object {
    $_.Name -cmatch '^ai-security-scanner-recovery-[0-9a-f]{32}$'
  })
  if ($remainingDistribution.Count -ne 0 -or $remainingQuarantine.Count -ne 0) {
    throw "Managed runtime cleanup retained an exact or quarantine WSL registration."
  }
  Invoke-ExactProcess $candidateUninstaller @("/S", "_?=$installDirectory") 180000 "Candidate NSIS cleanup uninstall" | Out-Null
  $activeCli = $null
  $postUninstallConsumedProof = Assert-OwnerOnlyFullControlFile $consumedProofPath (
    "Consumed proof retained until explicit private-data cleanup"
  ) (64 * 1024)
  if ($postUninstallConsumedProof.Length -ne $consumedProofItem.Length -or
      (Get-LowerSha256 $consumedProofPath (64 * 1024)) -cne $consumedProofSha256) {
    throw "NSIS uninstall changed or removed the permanent consumed proof before explicit private-data cleanup."
  }
  if (Test-Path -LiteralPath $installDirectory) {
    Remove-ExactTree $installDirectory $localApplicationData "ai-security-scanner" "Default NSIS install directory cleanup"
  }
  Remove-ExactTree $dataDirectory $localApplicationData "dev.teddashh.ai-security-scanner" "Default private data cleanup"
  if (@(Get-ProductRegistryEntries).Count -ne 0) { throw "Candidate uninstaller left the product registry entry." }
  $activeUninstaller = $null
  $cleanupComplete = $true

  $observations = [ordered]@{
    schemaVersion = 1
    scenario = "real_registered_wsl_n_minus_one_ghost_install_recovery"
    platform = "windows-x86_64"
    runner = "windows-2025"
    priorRelease = [ordered]@{
      version = $priorVersion
      tag = "v0.1.7"
      installerFile = $priorInstallerName
      installerBytes = $priorInstallerBytes
      installerSha256 = $priorInstallerSha256
      downloadUrl = $priorInstallerUrl
      runtimeManifestSha256 = $priorRuntimeManifestSha256
      machineImageSha256 = $priorMachineImageSha256
    }
    candidate = [ordered]@{
      version = $CurrentVersion
      installerFile = [string]$candidateRecords[0].file
      installerBytes = [int64]$candidateRecords[0].bytes
      installerSha256 = $candidateInstallerSha256
      runtimeManifestSha256 = $candidateRuntimeManifestSha256
      machineImageSha256 = $candidateMachineImageSha256
    }
    ghostFixture = [ordered]@{
      defaultInstallDirectoryUsed = $true
      priorCliVersion = $priorCliVersion
      oldRegistryIdentityExact = $true
      oldRuntimeInstalled = ($oldInstallStatus.manifest_sha256 -ceq $priorRuntimeManifestSha256)
      oldRuntimeStarted = $true
      oldRuntimeStopped = $true
      oldProviderNamespace = $priorProviderNamespace
      oldProviderCryptographicIdentityPresent = $true
      distributionName = $oldDistributionName
      registeredWslStateExercised = $true
      registrationBoundToOldProvider = $true
      oldVersionDirectory = $oldVersionDirectoryName
      oldVersionPayloadDigestVerifiedBeforeRemoval = $true
      oldVersionPayloadDirectoryRemoved = $true
      oldDesktopRemoved = $true
      oldUninstallerRemoved = $true
    }
    installerMigration = [ordered]@{
      candidateInstallerCompleted = $true
      transitionReceipt = $installerTransitionReceipt
      candidateCliVersion = $candidateCliVersion
      registryVersionUpdated = $true
      registryIdentityExact = $true
      candidateDesktopRestored = $true
      candidateUninstallerRestored = $true
      candidateRuntimeResourceMatchesRelease = $true
      exactPrivateDataSnapshotPreserved = $true
      sameVersionSilentReinstallCompleted = $true
      transitionReceiptSurvivedSameVersionReinstall = $true
    }
    runtimeRecovery = [ordered]@{
      startSucceeded = $true
      noManualActionFallback = $true
      runningAndAvailable = $true
      sameDistributionName = $true
      registrationMovedToCurrentProvider = $true
      currentProviderNamespace = $candidateProviderNamespace
      oldProviderRemoved = $true
      recoveryId = $recoveryId
      durableIntentPresent = $true
      intentProofValid = $true
      intentSchemaVersion = [string]$intent.schema_version
      intentOwnershipBasis = [string]$intent.ownership_basis
      intentManifestSha256 = [string]$intent.manifest_sha256
      intentMachineImageSha256 = [string]$intent.machine_image_sha256
      intentSourceProviderManifestSha256 = [string]$intent.source_provider_manifest_sha256
      intentTransitionReceipt = [string]$intent.install_transition_receipt
      receiptConsumption = [ordered]@{
        registryValueAbsent = $true
        proofPathExact = $true
        proofPresent = $true
        proofProtected = $true
        proofBytes = [int64]$consumedProofItem.Length
        proofSha256 = $consumedProofSha256
        schemaVersion = [string]$consumedProof.schema_version
        recoveryId = [string]$consumedProof.recovery_id
        installTransitionReceipt = [string]$consumedProof.install_transition_receipt
        sourceProviderManifestSha256 = [string]$consumedProof.source_provider_manifest_sha256
        manifestSha256 = [string]$consumedProof.manifest_sha256
        machineImageSha256 = [string]$consumedProof.machine_image_sha256
        machineName = [string]$consumedProof.machine_name
        distributionName = [string]$consumedProof.distribution_name
        proofRetainedAfterRuntimePurge = $true
        proofRetainedUntilExplicitPrivateDataCleanup = $true
      }
      durableArchivePresent = $true
      archiveBytes = [int64]$archiveItem.Length
      archiveSha256 = $archiveSha256
      backupReceiptValid = $true
      importReceiptValid = $true
      backupAndImportAgree = $true
      pendingRecoveryAbsent = $true
      temporaryWorkspaceAbsent = $true
      quarantineDistributionAbsent = $true
    }
    dataPreservation = [ordered]@{
      preInstallerFileCount = [int]$beforeInstallerSnapshot.fileCount
      preInstallerBytes = [int64]$beforeInstallerSnapshot.totalBytes
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
      rotationIntentAbsent = $true
      continuityEvent = [string]$candidateSigningIdentity.continuity_event
      identityKeyId = [string]$candidateSigningIdentity.key_id
      identityPublicKeyBase64 = [string]$candidateSigningIdentity.public_key_base64
      firstBundleValid = $true
      secondBundleValid = $true
    }
    cleanup = [ordered]@{
      managedRuntimePurged = $true
      exactWslDistributionAbsent = $true
      quarantineDistributionsAbsent = $true
      candidateUninstalled = $true
      installDirectoryRemoved = $true
      privateDataRemoved = $true
      productRegistryRemoved = $true
    }
  }
} catch {
  $primaryFailure = $_
} finally {
  if ($null -ne $primaryFailure) {
    if ($null -ne $activeCli -and (Test-Path -LiteralPath $activeCli -PathType Leaf) -and
        (Test-Path -LiteralPath $dataDirectory -PathType Container)) {
      foreach ($cleanupArguments in @(
        @( "--json", "--data-dir", $dataDirectory, "runtime", "managed", "stop", "--force" ),
        @( "--json", "--data-dir", $dataDirectory, "runtime", "managed", "uninstall", "--force", "--purge-image-cache" )
      )) {
        try { Invoke-ExactProcess $activeCli $cleanupArguments 900000 "Failure-path managed runtime cleanup" $true | Out-Null }
        catch { $cleanupFailures.Add($_.Exception.Message) }
      }
    }
    try {
      $registrations = @(Get-WslRegistrations)
      foreach ($registration in $registrations) {
        $isExact = [String]::Equals($registration.Name, $oldDistributionName, [StringComparison]::Ordinal)
        $isQuarantine = $registration.Name -cmatch '^ai-security-scanner-recovery-[0-9a-f]{32}$'
        if (-not $isExact -and -not $isQuarantine) { continue }
        $basePath = Resolve-RealDirectory $registration.BasePath "Failure-path WSL registration BasePath"
        $managedRoot = [IO.Path]::GetFullPath((Join-Path $dataDirectory "managed-runtime")) + [IO.Path]::DirectorySeparatorChar
        if (-not $basePath.StartsWith($managedRoot, [StringComparison]::OrdinalIgnoreCase)) {
          throw "Refusing to unregister a WSL distribution outside the exact qualification data root."
        }
        Unregister-ProvenExactWsl $trustedWsl $registration.Name
      }
    } catch { $cleanupFailures.Add($_.Exception.Message) }
    if ($null -ne $activeUninstaller -and (Test-Path -LiteralPath $activeUninstaller -PathType Leaf)) {
      try { Invoke-ExactProcess $activeUninstaller @("/S", "_?=$installDirectory") 180000 "Failure-path candidate uninstall" | Out-Null }
      catch { $cleanupFailures.Add($_.Exception.Message) }
    }
    foreach ($cleanup in @(
      [ordered]@{ path = $installDirectory; parent = $localApplicationData; name = "ai-security-scanner" },
      [ordered]@{ path = $dataDirectory; parent = $localApplicationData; name = "dev.teddashh.ai-security-scanner" }
    )) {
      try {
        if (Test-Path -LiteralPath $cleanup.path) {
          Remove-ExactTree $cleanup.path $cleanup.parent $cleanup.name "Failure-path exact qualification tree"
        }
      } catch { $cleanupFailures.Add($_.Exception.Message) }
    }
    try {
      $entries = @(Get-ProductRegistryEntries)
      foreach ($entry in $entries) {
        if ($entry.KeyName -cne "ai-security-scanner") { throw "Refusing unexpected product registry cleanup." }
        Remove-Item -LiteralPath $entry.KeyPath -Recurse -Force
      }
    } catch { $cleanupFailures.Add($_.Exception.Message) }
  }
}

if ($null -ne $primaryFailure) {
  $suffix = if ($cleanupFailures.Count -eq 0) { "" } else { " Cleanup failure(s): $([String]::Join('; ', $cleanupFailures))" }
  throw [InvalidOperationException]::new($primaryFailure.Exception.Message + $suffix, $primaryFailure.Exception)
}
if (-not $cleanupComplete -or $null -eq $observations) {
  throw "Real registered-WSL ghost qualification did not reach its verified cleanup state."
}
$observationsPath = Join-Path $workRoot "observations.json"
$observations | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $observationsPath -Encoding utf8NoBOM -NoNewline
Add-Content -LiteralPath $observationsPath -Value "" -Encoding utf8NoBOM
