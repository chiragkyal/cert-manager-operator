#!/bin/bash
# Install OpenSpec Codex commands from .cursor/commands/ to global ~/.codex/prompts/
# Usage: ./scripts/install-codex-commands.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
SOURCE_DIR="$PROJECT_ROOT/.cursor/commands"
DEST_DIR="$HOME/.codex/prompts"

echo "📦 Installing OpenSpec Codex commands..."
echo "  Source: $SOURCE_DIR"
echo "  Destination: $DEST_DIR"

# Create destination directory if it doesn't exist
mkdir -p "$DEST_DIR"

# Copy all command files
if [ -d "$SOURCE_DIR" ]; then
    cp "$SOURCE_DIR"/*.md "$DEST_DIR/" || {
        echo "❌ Error: Could not copy command files"
        exit 1
    }
    echo "✅ Successfully installed $(ls $SOURCE_DIR/*.md | wc -l) commands to $DEST_DIR"
    echo ""
    echo "📋 Installed commands:"
    ls -1 "$SOURCE_DIR"/*.md | xargs -n1 basename | sort
    echo ""
    echo "🚀 Restart Codex to pick up the new commands"
else
    echo "❌ Error: Source directory not found: $SOURCE_DIR"
    exit 1
fi
