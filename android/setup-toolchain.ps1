$ErrorActionPreference = "Stop"

$ProjectRoot = Split-Path -Parent $PSScriptRoot
$ToolchainRoot = Join-Path $ProjectRoot ".toolchains"
$SdkRoot = Join-Path $ToolchainRoot "android-sdk"
$DownloadRoot = Join-Path $ToolchainRoot "downloads"
$JdkArchive = Join-Path $DownloadRoot "temurin-jdk17.zip"
$CommandLineToolsArchive = Join-Path $DownloadRoot "android-commandlinetools.zip"
$GoArchive = Join-Path $DownloadRoot "go1.27.1.windows-amd64.zip"
$GoHome = Join-Path $ToolchainRoot "go"

New-Item -ItemType Directory -Force -Path $ToolchainRoot, $SdkRoot, $DownloadRoot | Out-Null

$JdkHome = Get-ChildItem -Path $ToolchainRoot -Directory -Filter "jdk-17*" -ErrorAction SilentlyContinue |
    Select-Object -First 1 -ExpandProperty FullName

if (-not $JdkHome) {
    Write-Host "Downloading Eclipse Temurin JDK 17..."
    if (-not (Test-Path $JdkArchive)) {
        Invoke-WebRequest `
            -Uri "https://api.adoptium.net/v3/binary/latest/17/ga/windows/x64/jdk/hotspot/normal/eclipse" `
            -OutFile $JdkArchive
    }
    Expand-Archive -Path $JdkArchive -DestinationPath $ToolchainRoot -Force
    $JdkHome = Get-ChildItem -Path $ToolchainRoot -Directory -Filter "jdk-17*" |
        Select-Object -First 1 -ExpandProperty FullName
}

if (-not $JdkHome) {
    throw "JDK 17 was not installed"
}

$env:JAVA_HOME = $JdkHome

if (-not (Test-Path (Join-Path $GoHome "bin\go.exe"))) {
    Write-Host "Downloading Go 1.27.1..."
    if (-not (Test-Path $GoArchive)) {
        Invoke-WebRequest `
            -Uri "https://go.dev/dl/go1.27.1.windows-amd64.zip" `
            -OutFile $GoArchive
    }
    $ExpectedGoHash = "A3911B5E0E1B1053F25ED0675F4C1C6AAD1E2BFCF253DF2B9BE4CAABD2EDD95D"
    $ActualGoHash = (Get-FileHash -Path $GoArchive -Algorithm SHA256).Hash
    if ($ActualGoHash -ne $ExpectedGoHash) {
        throw "Go checksum mismatch: $ActualGoHash"
    }
    $GoUnpackRoot = Join-Path $ToolchainRoot "go-unpack"
    if (Test-Path $GoUnpackRoot) {
        Remove-Item -LiteralPath $GoUnpackRoot -Recurse -Force
    }
    New-Item -ItemType Directory -Force -Path $GoUnpackRoot | Out-Null
    Expand-Archive -Path $GoArchive -DestinationPath $GoUnpackRoot -Force
    if (Test-Path $GoHome) {
        Remove-Item -LiteralPath $GoHome -Recurse -Force
    }
    Move-Item -LiteralPath (Join-Path $GoUnpackRoot "go") -Destination $GoHome
    Remove-Item -LiteralPath $GoUnpackRoot -Recurse -Force
}

$env:Path = "$JdkHome\bin;$GoHome\bin;$env:Path"

$SdkManager = Join-Path $SdkRoot "cmdline-tools\latest\bin\sdkmanager.bat"
if (-not (Test-Path $SdkManager)) {
    Write-Host "Downloading Android command-line tools..."
    if (-not (Test-Path $CommandLineToolsArchive)) {
        Invoke-WebRequest `
            -Uri "https://dl.google.com/android/repository/commandlinetools-win-15859902_latest.zip" `
            -OutFile $CommandLineToolsArchive
    }

    $ExpectedHash = "90AE805D20434428BFFCB699C290860F19BB5F66A67E6B330067E3DE801FB04A"
    $ActualHash = (Get-FileHash -Path $CommandLineToolsArchive -Algorithm SHA256).Hash
    if ($ActualHash -ne $ExpectedHash) {
        throw "Android command-line tools checksum mismatch: $ActualHash"
    }

    $UnpackRoot = Join-Path $ToolchainRoot "android-cli-unpack"
    if (Test-Path $UnpackRoot) {
        Remove-Item -LiteralPath $UnpackRoot -Recurse -Force
    }
    Expand-Archive -Path $CommandLineToolsArchive -DestinationPath $UnpackRoot -Force
    $LatestRoot = Join-Path $SdkRoot "cmdline-tools\latest"
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $LatestRoot) | Out-Null
    Move-Item -LiteralPath (Join-Path $UnpackRoot "cmdline-tools") -Destination $LatestRoot
    Remove-Item -LiteralPath $UnpackRoot -Recurse -Force
}

$env:ANDROID_HOME = $SdkRoot
$env:ANDROID_SDK_ROOT = $SdkRoot

Write-Host "Accepting Android SDK licenses..."
1..100 | ForEach-Object { "y" } | & $SdkManager --sdk_root=$SdkRoot --licenses | Out-Host

Write-Host "Installing Android SDK, NDK, and CMake..."
& $SdkManager --sdk_root=$SdkRoot `
    "platform-tools" `
    "platforms;android-34" `
    "build-tools;34.0.0" `
    "ndk;25.1.8937393" `
    "cmake;3.22.1"

$LocalProperties = Join-Path $PSScriptRoot "local.properties"
$SdkProperty = $SdkRoot.Replace("\", "/")
Set-Content -Path $LocalProperties -Encoding ASCII -Value "sdk.dir=$SdkProperty"

Write-Host "JAVA_HOME=$JdkHome"
Write-Host "GOROOT=$GoHome"
Write-Host "ANDROID_SDK_ROOT=$SdkRoot"
Write-Host "Android toolchain is ready."
