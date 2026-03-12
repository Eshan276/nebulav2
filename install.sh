#!/bin/sh
set -e

REPO="Eshan276/nebulav2"
VERSION="v0.1.0"
BINARY="nebula"
INSTALL_DIR="$HOME/.local/bin"

# Detect OS and arch
OS="$(uname -s)"
ARCH="$(uname -m)"

case "$OS" in
  Linux)
    case "$ARCH" in
      x86_64) ASSET="nebula-linux-x86_64" ;;
      *) echo "Unsupported architecture: $ARCH"; exit 1 ;;
    esac
    ;;
  Darwin)
    case "$ARCH" in
      arm64)  ASSET="nebula-macos-aarch64" ;;
      x86_64) ASSET="nebula-macos-x86_64" ;;
      *) echo "Unsupported architecture: $ARCH"; exit 1 ;;
    esac
    ;;
  *)
    echo "Unsupported OS: $OS"
    exit 1
    ;;
esac

URL="https://github.com/$REPO/releases/download/$VERSION/$ASSET"

echo "Installing nebula $VERSION..."
echo "Downloading from $URL"

mkdir -p "$INSTALL_DIR"
curl -fsSL "$URL" -o "$INSTALL_DIR/$BINARY"
chmod +x "$INSTALL_DIR/$BINARY"

# Check if INSTALL_DIR is in PATH
case ":$PATH:" in
  *":$INSTALL_DIR:"*)
    ;;
  *)
    echo ""
    echo "Add this to your shell profile (~/.bashrc or ~/.zshrc):"
    echo "  export PATH=\"\$HOME/.local/bin:\$PATH\""
    echo ""
    echo "Then run: source ~/.bashrc"
    ;;
esac

echo "Done! Run: nebula --help"
