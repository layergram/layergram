$ErrorActionPreference = 'Stop'

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$CrateDirectory = Join-Path $RepoRoot 'native\layergram_scka'
$TargetRoot = if ($env:LAYERGRAM_SCKA_CANDIDATE_TARGET_DIR) {
  $env:LAYERGRAM_SCKA_CANDIDATE_TARGET_DIR
} else {
  Join-Path $RepoRoot '.dart_tool\layergram_pq'
}
$ScaffoldTarget = Join-Path $TargetRoot 'scka-scaffold'
$CandidateTarget = Join-Path $TargetRoot 'scka-candidate'
$DartVersion = (& dart --version 2>&1 | Out-String).Trim()
$RustTarget = if ($DartVersion -match 'windows_x64') {
  'x86_64-pc-windows-msvc'
} elseif ($DartVersion -match 'windows_arm64') {
  'aarch64-pc-windows-msvc'
} else {
  throw "Unsupported Dart Windows architecture: $DartVersion"
}
$ScaffoldLibrary = Join-Path $ScaffoldTarget "$RustTarget\release\layergram_scka.dll"
$CandidateLibrary = Join-Path $CandidateTarget "$RustTarget\release\layergram_scka.dll"

Push-Location $CrateDirectory
try {
  cargo test --locked --offline
  if ($LASTEXITCODE -ne 0) { throw 'Default SCKA Rust tests failed' }
  cargo test --locked --offline --features candidate-ffi
  if ($LASTEXITCODE -ne 0) { throw 'Candidate SCKA Rust tests failed' }
  cargo clippy --locked --offline --all-targets -- -D warnings
  if ($LASTEXITCODE -ne 0) { throw 'Default SCKA Clippy failed' }
  cargo clippy --locked --offline --all-targets --features candidate-ffi -- -D warnings
  if ($LASTEXITCODE -ne 0) { throw 'Candidate SCKA Clippy failed' }
  cargo build --locked --offline --release --target $RustTarget --target-dir $ScaffoldTarget
  if ($LASTEXITCODE -ne 0) { throw 'Default SCKA release build failed' }
  cargo build --locked --offline --release --features candidate-ffi --target $RustTarget --target-dir $CandidateTarget
  if ($LASTEXITCODE -ne 0) { throw 'Candidate SCKA release build failed' }
} finally {
  Pop-Location
}

Push-Location $RepoRoot
try {
  flutter analyze lib/core/crypto/v3/scka_candidate_ffi.dart test/core/crypto/v3/scka_candidate_ffi_integration_test.dart
  if ($LASTEXITCODE -ne 0) { throw 'SCKA candidate Dart analysis failed' }
  $env:LAYERGRAM_SCKA_SCAFFOLD_LIBRARY = $ScaffoldLibrary
  $env:LAYERGRAM_SCKA_CANDIDATE_LIBRARY = $CandidateLibrary
  flutter test test/core/crypto/v3/scka_candidate_ffi_integration_test.dart
  if ($LASTEXITCODE -ne 0) { throw 'SCKA candidate Dart integration failed' }
} finally {
  Remove-Item Env:LAYERGRAM_SCKA_SCAFFOLD_LIBRARY -ErrorAction SilentlyContinue
  Remove-Item Env:LAYERGRAM_SCKA_CANDIDATE_LIBRARY -ErrorAction SilentlyContinue
  Pop-Location
}

Write-Output 'LAYERGRAM_SCKA_CANDIDATE_FFI_WINDOWS_OK'
