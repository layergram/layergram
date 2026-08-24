$ErrorActionPreference = 'Stop'

$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$sourceDirectory = Join-Path $repositoryRoot 'windows\mlkem'
$buildDirectory = Join-Path $repositoryRoot '.dart_tool\layergram_pq\windows-native'
$vswhere = Join-Path ${env:ProgramFiles(x86)} `
  'Microsoft Visual Studio\Installer\vswhere.exe'

if (-not (Test-Path $vswhere -PathType Leaf)) {
  throw "Visual Studio Installer vswhere.exe was not found at $vswhere"
}

$visualStudioPath = (& $vswhere -latest -products * `
    -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 `
    -property installationPath).Trim()
if (-not $visualStudioPath) {
  throw 'A Visual Studio installation with the C++ toolchain was not found'
}

$cmakeDirectory = Join-Path $visualStudioPath `
  'Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin'
$cmake = Join-Path $cmakeDirectory 'cmake.exe'
$ctest = Join-Path $cmakeDirectory 'ctest.exe'
if (-not (Test-Path $cmake -PathType Leaf) -or `
    -not (Test-Path $ctest -PathType Leaf)) {
  throw "Visual Studio CMake tools were not found below $cmakeDirectory"
}

& $cmake -S $sourceDirectory -B $buildDirectory -A x64 `
  -DLAYERGRAM_MLKEM_TESTING=ON
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

& $cmake --build $buildDirectory --config Release
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

& $ctest --test-dir $buildDirectory -C Release --output-on-failure
exit $LASTEXITCODE
