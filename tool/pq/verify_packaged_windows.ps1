$ErrorActionPreference = 'Stop'

$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$releaseDirectory = Join-Path $repositoryRoot `
  'build\windows\x64\runner\Release'
$library = Join-Path $releaseDirectory 'layergram_mlkem.dll'
$executable = Join-Path $releaseDirectory 'layergram.exe'
$msix = Join-Path $releaseDirectory 'layergram.msix'
$vswhere = Join-Path ${env:ProgramFiles(x86)} `
  'Microsoft Visual Studio\Installer\vswhere.exe'

foreach ($artifact in @($library, $executable, $vswhere)) {
  if (-not (Test-Path $artifact -PathType Leaf)) {
    throw "Required Windows artifact was not found: $artifact"
  }
}

$visualStudioPath = (& $vswhere -latest -products * `
    -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 `
    -property installationPath).Trim()
if (-not $visualStudioPath) {
  throw 'A Visual Studio installation with the C++ toolchain was not found'
}

$dumpbin = Get-ChildItem `
  (Join-Path $visualStudioPath 'VC\Tools\MSVC\*\bin\Host*\x64\dumpbin.exe') |
  Sort-Object FullName |
  Select-Object -Last 1 -ExpandProperty FullName
if (-not $dumpbin) {
  throw 'Visual Studio dumpbin.exe for x64 was not found'
}

$headers = (& $dumpbin /nologo /headers $library) -join "`n"
if ($headers -notmatch '(?im)^\s*8664 machine \(x64\)\s*$') {
  throw 'The packaged ML-KEM DLL is not a Windows x64 binary'
}
$dependencies = (& $dumpbin /nologo /dependents $library) -join "`n"
if ($dependencies -notmatch '(?im)^\s*BCRYPT\.dll\s*$') {
  throw 'The packaged ML-KEM DLL does not depend on Windows BCrypt'
}

$expectedSymbols = @(
  'lg_mlkem768_abi_version'
  'lg_mlkem768_ciphertext_bytes'
  'lg_mlkem768_decapsulate'
  'lg_mlkem768_encaps_seed_bytes'
  'lg_mlkem768_encapsulate'
  'lg_mlkem768_implementation_id'
  'lg_mlkem768_keygen_seed_bytes'
  'lg_mlkem768_keypair_from_seed'
  'lg_mlkem768_private_key_bytes'
  'lg_mlkem768_private_key_destroy'
  'lg_mlkem768_public_key_bytes'
  'lg_mlkem768_self_test'
  'lg_mlkem768_shared_secret_bytes'
  'lg_mlkem768_validate_public_key'
)

$actualSymbols = @(
  & $dumpbin /nologo /exports $library |
    ForEach-Object {
      if ($_ -match '^\s+\d+\s+[0-9A-F]+\s+[0-9A-F]+\s+(\S+)\s*$') {
        $Matches[1]
      }
    } |
    Sort-Object -Unique
)
$difference = @(Compare-Object $expectedSymbols $actualSymbols)
if ($difference.Count -ne 0) {
  $difference | Format-Table -AutoSize | Out-String | Write-Error
  throw 'The packaged Windows ML-KEM export surface is not exact'
}

if (Test-Path $msix -PathType Leaf) {
  Add-Type -AssemblyName System.IO.Compression.FileSystem
  $archive = [System.IO.Compression.ZipFile]::OpenRead($msix)
  try {
    $packagedLibrary = $archive.Entries |
      Where-Object { $_.FullName -eq 'layergram_mlkem.dll' }
    if (-not $packagedLibrary) {
      throw 'The generated MSIX does not contain layergram_mlkem.dll'
    }
  }
  finally {
    $archive.Dispose()
  }
}

Write-Output 'LAYERGRAM_MLKEM_PACKAGED_WINDOWS_OK'
