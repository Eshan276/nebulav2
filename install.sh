#!/bin/sh
set -e

REPO="Eshan276/nebulav2"
VERSION="v0.2.4"
INSTALL_DIR="$HOME/.local/bin"

STELLAR_VERSION="v23.4.1"

# Detect OS and arch
OS="$(uname -s)"
ARCH="$(uname -m)"

case "$OS" in
  Linux)
    case "$ARCH" in
      x86_64)
        NEBULA_ASSET="nebula-linux-x86_64"
        XMSS_ASSET="xmss-linux-x86_64"
        STELLAR_ASSET="stellar-cli-${STELLAR_VERSION}-x86_64-unknown-linux-gnu.tar.gz"
        ;;
      *) echo "Unsupported architecture: $ARCH"; exit 1 ;;
    esac
    ;;
  Darwin)
    case "$ARCH" in
      arm64)
        NEBULA_ASSET="nebula-macos-aarch64"
        XMSS_ASSET="xmss-macos-aarch64"
        STELLAR_ASSET="stellar-cli-${STELLAR_VERSION}-aarch64-apple-darwin.tar.gz"
        ;;
      x86_64)
        NEBULA_ASSET="nebula-macos-x86_64"
        XMSS_ASSET="xmss-macos-x86_64"
        STELLAR_ASSET="stellar-cli-${STELLAR_VERSION}-x86_64-apple-darwin.tar.gz"
        ;;
      *) echo "Unsupported architecture: $ARCH"; exit 1 ;;
    esac
    ;;
  *)
    echo "Unsupported OS: $OS"
    exit 1
    ;;
esac

mkdir -p "$INSTALL_DIR"

# ── nebula ────────────────────────────────────────────────────────────────────
echo "Installing nebula ${VERSION}..."
curl -fsSL "https://github.com/$REPO/releases/download/$VERSION/$NEBULA_ASSET" \
  -o "$INSTALL_DIR/nebula"
chmod +x "$INSTALL_DIR/nebula"
echo "  nebula installed"

# ── xmss ─────────────────────────────────────────────────────────────────────
echo "Installing xmss..."
curl -fsSL "https://github.com/$REPO/releases/download/$VERSION/$XMSS_ASSET" \
  -o "$INSTALL_DIR/xmss"
chmod +x "$INSTALL_DIR/xmss"
echo "  xmss installed"

# ── stellar CLI ───────────────────────────────────────────────────────────────
if command -v stellar >/dev/null 2>&1; then
  echo "stellar CLI already installed ($(stellar --version 2>/dev/null || echo 'unknown version'))"
else
  echo "Installing Stellar CLI ${STELLAR_VERSION}..."
  STELLAR_URL="https://github.com/stellar/stellar-cli/releases/download/${STELLAR_VERSION}/${STELLAR_ASSET}"
  curl -fsSL "$STELLAR_URL" | tar xz -C "$INSTALL_DIR" stellar
  chmod +x "$INSTALL_DIR/stellar"
  echo "  stellar CLI installed"
fi

# ── PATH check ────────────────────────────────────────────────────────────────
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

echo ""
echo "Done! Run: nebula --help"
