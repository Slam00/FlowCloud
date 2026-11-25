#!/usr/bin/env bash
# Linux/macOS counterpart of build-flowrouter.ps1: builds libflowrouter.so for
# every ABI with the Android NDK. Uses GO (default: go on PATH) and
# ANDROID_NDK_HOME / ANDROID_NDK_ROOT (default: $ANDROID_HOME/ndk/25.1.8937393).
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source_root="$script_dir/flowrouter"
output_root="$source_root/build/jniLibs"
go_bin="${GO:-go}"
ndk_version="25.1.8937393"
ndk_root="${ANDROID_NDK_HOME:-${ANDROID_NDK_ROOT:-${ANDROID_HOME:-${ANDROID_SDK_ROOT:-}}/ndk/$ndk_version}}"

case "$(uname -s)" in
    Linux) host_tag="linux-x86_64" ;;
    Darwin) host_tag="darwin-x86_64" ;;
    *) echo "Unsupported host: $(uname -s); use build-flowrouter.ps1 on Windows" >&2; exit 1 ;;
esac
toolchain="$ndk_root/toolchains/llvm/prebuilt/$host_tag/bin"

if ! command -v "$go_bin" >/dev/null 2>&1; then
    echo "Go is missing: install it or set GO" >&2
    exit 1
fi
if [ ! -d "$toolchain" ]; then
    echo "Android NDK toolchain not found at $toolchain" >&2
    exit 1
fi

export GOOS=android
export CGO_ENABLED=1
export GOCACHE="$source_root/build/cache"
export CGO_LDFLAGS="-Wl,-z,max-page-size=16384 -Wl,-z,common-page-size=16384"
mkdir -p "$GOCACHE"

# ABI, GOARCH, GOARM, clang wrapper (API 24, matching minSdk).
targets=(
    "armeabi-v7a arm 7 armv7a-linux-androideabi24-clang"
    "arm64-v8a arm64 - aarch64-linux-android24-clang"
    "x86 386 - i686-linux-android24-clang"
    "x86_64 amd64 - x86_64-linux-android24-clang"
)

for target in "${targets[@]}"; do
    read -r abi arch arm cc <<<"$target"
    export GOARCH="$arch"
    if [ "$arm" = "-" ]; then unset GOARM; else export GOARM="$arm"; fi
    export CC="$toolchain/$cc"
    mkdir -p "$output_root/$abi"
    echo "Building flow router for $abi..."
    "$go_bin" -C "$source_root" build -trimpath -buildmode=c-shared -ldflags='-s -w' \
        -o "$output_root/$abi/libflowrouter.so" .
done
