$ErrorActionPreference = 'Stop'

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$crateDirectory = Join-Path $repoRoot 'native\layergram_scka'
$targetDirectory = if ($env:LAYERGRAM_SCKA_WINDOWS_TARGET_DIR) {
  $env:LAYERGRAM_SCKA_WINDOWS_TARGET_DIR
} else {
  Join-Path $repoRoot '.dart_tool\layergram_pq\scka-rust-windows'
}

$cargo = (Get-Command cargo.exe -ErrorAction Stop).Source
$rustc = (Get-Command rustc.exe -ErrorAction Stop).Source
$rustVersion = (& $rustc --version).Split(' ')[1]
if ($rustVersion -ne '1.87.0') {
  throw "Layergram SCKA scaffold requires Rust 1.87.0, found $rustVersion"
}
& $cargo test --locked --offline `
  --manifest-path (Join-Path $crateDirectory 'Cargo.toml') `
  --target-dir $targetDirectory
if ($LASTEXITCODE -ne 0) { throw 'Layergram SCKA Rust tests failed' }

& $cargo build --release --locked --offline `
  --manifest-path (Join-Path $crateDirectory 'Cargo.toml') `
  --target-dir $targetDirectory
if ($LASTEXITCODE -ne 0) { throw 'Layergram SCKA Rust release build failed' }

$library = Join-Path $targetDirectory 'release\layergram_scka.dll'
if (-not (Test-Path -LiteralPath $library -PathType Leaf)) {
  throw "Missing SCKA scaffold library: $library"
}

$vswhere = Join-Path ${env:ProgramFiles(x86)} `
  'Microsoft Visual Studio\Installer\vswhere.exe'
if (-not (Test-Path -LiteralPath $vswhere -PathType Leaf)) {
  throw 'Visual Studio vswhere.exe was not found'
}
$installationPath = (& $vswhere -latest -products * `
  -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 `
  -property installationPath | Select-Object -First 1)
if (-not $installationPath) { throw 'MSVC x64 tools were not found' }
$dumpbin = Get-ChildItem -LiteralPath (Join-Path $installationPath 'VC\Tools\MSVC') `
  -Filter dumpbin.exe -File -Recurse | Where-Object {
    $_.FullName -match '\\bin\\Hostx64\\x64\\dumpbin\.exe$'
  } | Sort-Object FullName -Descending | Select-Object -First 1
if (-not $dumpbin) { throw 'MSVC dumpbin.exe was not found' }

$expected = @(
  'lg_scka_v1_abi_version',
  'lg_scka_v1_epoch_secret_bytes',
  'lg_scka_v1_implementation_id',
  'lg_scka_v1_initialize',
  'lg_scka_v1_max_message_bytes',
  'lg_scka_v1_max_state_bytes',
  'lg_scka_v1_min_state_bytes',
  'lg_scka_v1_protocol_revision',
  'lg_scka_v1_receive',
  'lg_scka_v1_self_test',
  'lg_scka_v1_send',
  'lg_scka_v1_session_id_bytes',
  'lg_scka_v1_state_format_version',
  'lg_scka_v1_state_header_bytes',
  'lg_scka_v1_state_key_bytes',
  'lg_scka_v1_state_tag_bytes',
  'lg_scka_v1_state_validate'
) | Sort-Object -Unique
$actual = (& $dumpbin.FullName /nologo /exports $library) |
  Select-String -AllMatches -Pattern 'lg_scka_v1_[A-Za-z0-9_]+' |
  ForEach-Object { $_.Matches.Value } | Sort-Object -Unique
$difference = Compare-Object -ReferenceObject $expected -DifferenceObject $actual
if ($difference) {
  $difference | Out-String | Write-Error
  throw 'Unexpected Layergram SCKA Windows export surface'
}

Write-Output 'LAYERGRAM_SCKA_SCAFFOLD_WINDOWS_OK'
