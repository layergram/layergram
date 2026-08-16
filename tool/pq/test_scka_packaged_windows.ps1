$ErrorActionPreference = 'Stop'

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$crateDir = Join-Path $repoRoot 'native\layergram_scka'
$packageRoot = Join-Path $repoRoot '.dart_tool\layergram_pq\scka-package\windows'
$targetDir = Join-Path $packageRoot 'target'
$releaseDir = Join-Path $repoRoot 'build\windows\x64\runner\Release'
$library = Join-Path $releaseDir 'layergram_scka.dll'
$executable = Join-Path $releaseDir 'layergram.exe'
$symbolsFile = Join-Path $PSScriptRoot 'scka_expected_symbols.txt'
$rustTarget = 'x86_64-pc-windows-msvc'

$rustVersion = (& rustc --version).Split(' ')[1]
if ($rustVersion -ne '1.87.0') {
  throw "Layergram SCKA packaging requires Rust 1.87.0, found $rustVersion"
}
& rustup target list --installed | Select-String -SimpleMatch $rustTarget |
  Out-Null
if ($LASTEXITCODE -ne 0) {
  throw "Missing Rust target: $rustTarget"
}

& cargo build --release --locked --offline --features candidate-ffi `
  --manifest-path (Join-Path $crateDir 'Cargo.toml') `
  --target-dir $targetDir --target $rustTarget
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

& flutter build windows --release `
  -t tool\pq\scka_packaged_scope_smoke.dart
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
Copy-Item -Force `
  (Join-Path $targetDir "$rustTarget\release\layergram_scka.dll") `
  $library

$vswhere = Join-Path ${env:ProgramFiles(x86)} `
  'Microsoft Visual Studio\Installer\vswhere.exe'
$visualStudioPath = (& $vswhere -latest -products * `
    -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 `
    -property installationPath).Trim()
$dumpbin = Get-ChildItem `
  (Join-Path $visualStudioPath 'VC\Tools\MSVC\*\bin\Host*\x64\dumpbin.exe') |
  Sort-Object FullName | Select-Object -Last 1 -ExpandProperty FullName
$actualSymbols = @(
  & $dumpbin /nologo /exports $library |
    ForEach-Object {
      if ($_ -match '^\s+\d+\s+[0-9A-F]+\s+[0-9A-F]+\s+(\S+)\s*$') {
        $Matches[1]
      }
    } | Sort-Object -Unique
)
$expectedSymbols = @(Get-Content $symbolsFile | Where-Object { $_ })
if (@(Compare-Object $expectedSymbols $actualSymbols).Count -ne 0) {
  throw 'Unexpected packaged Windows SCKA export surface'
}

$marker = Join-Path $packageRoot 'scope-ok.txt'
if (Test-Path $marker -PathType Leaf) {
  Remove-Item -Force $marker
}
$env:LAYERGRAM_SCKA_PACKAGED_MARKER = $marker
$process = Start-Process -FilePath $executable -Wait -PassThru
if ($process.ExitCode -ne 0) {
  throw "Packaged Windows SCKA process exited with $($process.ExitCode)"
}
if (-not (Test-Path $marker -PathType Leaf) -or
    (Get-Content $marker -Raw).Trim() -ne 'LAYERGRAM_SCKA_PACKAGED_SCOPE_OK') {
  throw 'Packaged Windows SCKA scope smoke did not complete'
}

Write-Output 'LAYERGRAM_SCKA_PACKAGED_WINDOWS_OK'
