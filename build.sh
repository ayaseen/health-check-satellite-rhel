#!/bin/bash
# build.sh
# Author: Amjad Yaseen
# Date: 2025-04-17
#
# This script builds the health-check-runner with the latest OpenShift version embedded
# into the binary. This ensures that air-gapped clusters can still perform
# accurate version comparison without needing internet access at runtime.

set -e

# Default target platform is the current OS
TARGET_PLATFORM=""

# Parse command line arguments
while [[ $# -gt 0 ]]; do
  key="$1"
  case $key in
    --macos)
      TARGET_PLATFORM="darwin"
      shift
      ;;
    --linux)
      TARGET_PLATFORM="linux"
      shift
      ;;
    --help)
      echo "Usage: $0 [--macos|--linux]"
      echo "  --macos: Build for macOS"
      echo "  --linux: Build for Linux"
      echo "  If no platform is specified, the current OS will be detected"
      exit 0
      ;;
    *)
      # Unknown option
      echo "Unknown option: $1"
      echo "Usage: $0 [--macos|--linux]"
      exit 1
      ;;
  esac
done

# If no platform specified, detect current OS
if [ -z "$TARGET_PLATFORM" ]; then
  if [[ "$OSTYPE" == "darwin"* ]]; then
    TARGET_PLATFORM="darwin"
  elif [[ "$OSTYPE" == "linux"* ]] || [[ -f "/proc/version" ]]; then
    TARGET_PLATFORM="linux"
  else
    echo "Could not determine OS type. Please specify target platform with --macos or --linux"
    exit 1
  fi
fi

echo "Building for platform: $TARGET_PLATFORM"

# For Linux, check and install UPX if needed
if [ "$TARGET_PLATFORM" == "linux" ]; then
  if ! command -v upx &>/dev/null; then
    echo "UPX not found. Attempting to install..."

    # Check if we're on a RHEL-based system
    if command -v dnf &>/dev/null; then
      echo "RHEL/Fedora/CentOS system detected (dnf available)"

      # First try EPEL if it's available
      if sudo dnf list installed epel-release &>/dev/null; then
        echo "EPEL repository is already installed"
      else
        echo "Installing EPEL repository..."
        sudo dnf install -y epel-release || echo "Could not install EPEL, will try alternative methods"
      fi

      # Try to install UPX
      if ! sudo dnf install -y upx; then
        echo "Failed to install UPX via dnf, trying alternative installation method..."

        # If dnf installation fails, try to download and install UPX manually
        TMP_DIR=$(mktemp -d)
        cd "$TMP_DIR"

        echo "Downloading UPX binary..."
        curl -L https://github.com/upx/upx/releases/download/v4.2.1/upx-4.2.1-amd64_linux.tar.xz -o upx.tar.xz

        echo "Extracting UPX..."
        tar -xf upx.tar.xz

        echo "Installing UPX to /usr/local/bin..."
        sudo cp upx-*/upx /usr/local/bin/
        sudo chmod +x /usr/local/bin/upx

        cd - > /dev/null
        rm -rf "$TMP_DIR"

        # Verify installation
        if ! command -v upx &>/dev/null; then
          echo "WARNING: Failed to install UPX. Compression will be skipped."
        else
          echo "UPX installed successfully!"
        fi
      else
        echo "UPX installed successfully via dnf!"
      fi
    elif command -v yum &>/dev/null; then
      echo "RHEL/CentOS system detected (yum available)"

      # Check for EPEL
      if sudo yum list installed epel-release &>/dev/null; then
        echo "EPEL repository is already installed"
      else
        echo "Installing EPEL repository..."
        sudo yum install -y epel-release || echo "Could not install EPEL, will try alternative methods"
      fi

      # Try to install UPX
      if ! sudo yum install -y upx; then
        echo "Failed to install UPX via yum, trying alternative installation method..."

        # If yum installation fails, try to download and install UPX manually
        TMP_DIR=$(mktemp -d)
        cd "$TMP_DIR"

        echo "Downloading UPX binary..."
        curl -L https://github.com/upx/upx/releases/download/v4.2.1/upx-4.2.1-amd64_linux.tar.xz -o upx.tar.xz

        echo "Extracting UPX..."
        tar -xf upx.tar.xz

        echo "Installing UPX to /usr/local/bin..."
        sudo cp upx-*/upx /usr/local/bin/
        sudo chmod +x /usr/local/bin/upx

        cd - > /dev/null
        rm -rf "$TMP_DIR"

        # Verify installation
        if ! command -v upx &>/dev/null; then
          echo "WARNING: Failed to install UPX. Compression will be skipped."
        else
          echo "UPX installed successfully!"
        fi
      else
        echo "UPX installed successfully via yum!"
      fi
    else
      echo "Could not detect package manager. Trying direct installation..."

      # Try to download and install UPX manually
      TMP_DIR=$(mktemp -d)
      cd "$TMP_DIR"

      echo "Downloading UPX binary..."
      curl -L https://github.com/upx/upx/releases/download/v4.2.1/upx-4.2.1-amd64_linux.tar.xz -o upx.tar.xz

      echo "Extracting UPX..."
      tar -xf upx.tar.xz

      echo "Installing UPX to /usr/local/bin..."
      sudo cp upx-*/upx /usr/local/bin/
      sudo chmod +x /usr/local/bin/upx

      cd - > /dev/null
      rm -rf "$TMP_DIR"

      # Verify installation
      if ! command -v upx &>/dev/null; then
        echo "WARNING: Failed to install UPX. Compression will be skipped."
      else
        echo "UPX installed successfully!"
      fi
    fi
  else
    echo "UPX is already installed."
  fi
fi


# Set up platform-specific build settings
BINARY_NAME="health-check-runner"

echo "Building health-check-runner with size optimizations..."
if [ "$TARGET_PLATFORM" == "darwin" ]; then
    echo "Building health-check-runner for macOS..."
    GOOS=darwin GOARCH=amd64 go build -ldflags="-s -w" -o "$BINARY_NAME"
elif [ "$TARGET_PLATFORM" == "linux" ]; then
    echo "Building health-check-runner for Linux..."
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o "$BINARY_NAME"
fi

# Apply UPX compression for Linux binaries only
if [ "$TARGET_PLATFORM" == "linux" ] && command -v upx &> /dev/null; then
    echo "Applying UPX compression to reduce binary size further..."
    upx -9 --best --lzma "$BINARY_NAME"
elif [ "$TARGET_PLATFORM" == "linux" ]; then
    echo "Note: UPX compression not applied - UPX installation failed or skipped."
fi

# For macOS, skip UPX compression
if [ "$TARGET_PLATFORM" == "darwin" ]; then
    echo "Skipping compression for macOS binary (not supported on this platform)."
fi

# Get the file size
if [ -f "$BINARY_NAME" ]; then
    if [[ "$TARGET_PLATFORM" == "darwin" ]]; then
        FILE_SIZE=$(stat -f "%z" "$BINARY_NAME")
        HUMAN_SIZE=$(du -h "$BINARY_NAME" | awk '{print $1}')
    else
        FILE_SIZE=$(stat -c "%s" "$BINARY_NAME")
        HUMAN_SIZE=$(du -h "$BINARY_NAME" | awk '{print $1}')
    fi
    echo "Build complete! File size: $HUMAN_SIZE ($FILE_SIZE bytes)"
else
    echo "Build failed: Binary file not found"
    exit 1
fi

echo "Created binary: $BINARY_NAME with OpenShift version $LATEST_VERSION embedded."