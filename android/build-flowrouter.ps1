$ErrorActionPreference = 'Stop'

$ProjectRoot = Split-Path -Parent $PSScriptRoot
$GoExe = Join-Path $ProjectRoot '.toolchains/go/bin/go.exe'
$NdkRoot = Join-Path $ProjectRoot '.toolchains/android-sdk/ndk/25.1.8937393'
$Toolchain = Join-Path $NdkRoot 'toolchains/llvm/prebuilt/windows-x86_64/bin'
$SourceRoot = Join-Path $PSScriptRoot 'flowrouter'
$OutputRoot = Join-Path $SourceRoot 'build/jniLibs'

if (-not (Test-Path $GoExe)) {
    throw 'Go is missing. Run setup-toolchain.ps1 first.'
}
if (-not (Test-Path $Toolchain)) {
    throw 'Android NDK is missing. Run setup-toolchain.ps1 first.'
}

$targets = @(
    @{ Abi = 'armeabi-v7a'; Arch = 'arm'; Arm = '7'; Cc = 'armv7a-linux-androideabi24-clang.cmd' },
    @{ Abi = 'arm64-v8a'; Arch = 'arm64'; Arm = ''; Cc = 'aarch64-linux-android24-clang.cmd' },
    @{ Abi = 'x86'; Arch = '386'; Arm = ''; Cc = 'i686-linux-android24-clang.cmd' },
    @{ Abi = 'x86_64'; Arch = 'amd64'; Arm = ''; Cc = 'x86_64-linux-android24-clang.cmd' }
)

$originalGoOs = $env:GOOS
$originalGoArch = $env:GOARCH
$originalGoArm = $env:GOARM
$originalCgo = $env:CGO_ENABLED
$originalCc = $env:CC
$originalCache = $env:GOCACHE
$originalCgoLdflags = $env:CGO_LDFLAGS
try {
    $env:GOOS = 'android'
    $env:CGO_ENABLED = '1'
    $env:GOCACHE = Join-Path $SourceRoot 'build/cache'
    $env:CGO_LDFLAGS = '-Wl,-z,max-page-size=16384 -Wl,-z,common-page-size=16384'
    New-Item -ItemType Directory -Force -Path $env:GOCACHE | Out-Null

    foreach ($target in $targets) {
        $env:GOARCH = $target.Arch
        $env:GOARM = $target.Arm
        $env:CC = Join-Path $Toolchain $target.Cc
        $abiOutput = Join-Path $OutputRoot $target.Abi
        New-Item -ItemType Directory -Force -Path $abiOutput | Out-Null
        $output = Join-Path $abiOutput 'libflowrouter.so'
        Write-Host "Building flow router for $($target.Abi)..."
        & $GoExe -C $SourceRoot build -trimpath -buildmode=c-shared -ldflags='-s -w' -o $output .
        if ($LASTEXITCODE -ne 0) {
            throw "Flow router build failed for $($target.Abi)"
        }
    }
}
finally {
    $env:GOOS = $originalGoOs
    $env:GOARCH = $originalGoArch
    $env:GOARM = $originalGoArm
    $env:CGO_ENABLED = $originalCgo
    $env:CC = $originalCc
    $env:GOCACHE = $originalCache
    $env:CGO_LDFLAGS = $originalCgoLdflags
}
