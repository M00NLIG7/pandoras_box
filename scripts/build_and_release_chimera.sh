#!/bin/bash
#
# build_and_release_chimera.sh
#
# Builds chimera for both Linux and Windows using cross,
# then creates a GitHub release with both binaries.
#
# Usage: ./scripts/build_and_release_chimera.sh [release-tag]
#

set -e  # Exit on error

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

RELEASE_TAG="${1:-CCDC-2024-2025}"

echo -e "${BLUE}==================================================================${NC}"
echo -e "${BLUE}  Chimera Cross-Compilation & Release Builder${NC}"
echo -e "${BLUE}==================================================================${NC}"
echo ""
echo "Release tag: $RELEASE_TAG"
echo ""

# Check if gh is installed
if ! command -v gh &> /dev/null; then
    echo -e "${RED}ERROR: GitHub CLI (gh) is not installed${NC}"
    echo "Install: https://cli.github.com/"
    exit 1
fi

# Check if cross is installed
if ! command -v cross &> /dev/null; then
    echo -e "${YELLOW}cross is not installed. Installing...${NC}"
    cargo install cross --git https://github.com/cross-rs/cross
fi

echo -e "${GREEN}Step 1: Delete existing release (if it exists)${NC}"
echo "---"
gh release delete "$RELEASE_TAG" --yes 2>/dev/null && echo "Deleted existing release" || echo "No existing release to delete"
echo ""

echo -e "${GREEN}Step 2: Delete existing tag (if it exists)${NC}"
echo "---"
git tag -d "$RELEASE_TAG" 2>/dev/null && echo "Deleted local tag" || echo "No local tag to delete"
git push origin ":refs/tags/$RELEASE_TAG" 2>/dev/null && echo "Deleted remote tag" || echo "No remote tag to delete"
echo ""

echo -e "${GREEN}Step 3: Build Linux binary${NC}"
echo "---"
cd chimera
echo "Building for x86_64-unknown-linux-gnu..."
cross build --release --target x86_64-unknown-linux-gnu --bin chimera
echo -e "${GREEN}✓ Linux build complete${NC}"
echo ""

echo -e "${GREEN}Step 4: Build Windows binary${NC}"
echo "---"
echo "Building for x86_64-pc-windows-gnu..."
cross build --release --target x86_64-pc-windows-gnu --bin chimera
echo -e "${GREEN}✓ Windows build complete${NC}"
echo ""

cd ..

echo -e "${GREEN}Step 5: Copy binaries to release directory${NC}"
echo "---"
mkdir -p release
cp target/x86_64-unknown-linux-gnu/release/chimera release/chimera-linux
cp target/x86_64-pc-windows-gnu/release/chimera.exe release/chimera.exe

echo "Verifying binaries..."
file release/chimera-linux
file release/chimera.exe
echo ""

echo "Binary sizes:"
ls -lh release/chimera-linux release/chimera.exe
echo ""

echo -e "${GREEN}Step 6: Create GitHub release${NC}"
echo "---"
echo "Creating release: $RELEASE_TAG"

# Create release with both binaries
gh release create "$RELEASE_TAG" \
    release/chimera-linux \
    release/chimera.exe \
    --title "Pandora's Box - Fixed Chimera" \
    --notes "## Chimera Bug Fixes

**29 stability bugs fixed**, including:
- 15 critical stability bugs in remote communication
- 14 additional production-readiness issues
- All bugs fixed with proper error handling

### Changes
- Fixed infinite retry loops with unbounded backoff
- Fixed panic-inducing unwrap() calls
- Fixed race conditions in shutdown logic
- Fixed memory leaks (unbounded task accumulation)
- Fixed connection cleanup issues
- Reduced excessive timeouts (300-500s → 60s)
- Fixed command injection vulnerabilities
- Fixed integer overflow risks

### Files
- \`chimera-linux\`: Linux x86_64 binary
- \`chimera.exe\`: Windows x86_64 binary

### Usage
\`\`\`bash
# Linux
chmod +x chimera-linux
./chimera-linux all -m 62

# Windows
chimera.exe all -m 62
\`\`\`

### Password Configuration
Default base password: \`Sudo!!UrM0m\`
Magic number: 62
Final password per host: \`Sudo!!UrM0m<last_ip_octet * 62>\`

To change password, rebuild with:
\`\`\`bash
APP_PASSWORD=\"YourPassword\" cargo build --release --bin chimera
\`\`\`

---
**Commit**: $(git rev-parse --short HEAD)
**Branch**: $(git branch --show-current)
**Built**: $(date -u +"%Y-%m-%d %H:%M:%S UTC")
"

echo ""
echo -e "${GREEN}✓ Release created successfully!${NC}"
echo ""

echo -e "${BLUE}Step 7: Display release info${NC}"
echo "---"
gh release view "$RELEASE_TAG"
echo ""

echo -e "${GREEN}==================================================================${NC}"
echo -e "${GREEN}  Build Complete!${NC}"
echo -e "${GREEN}==================================================================${NC}"
echo ""
echo "Release tag: $RELEASE_TAG"
echo "View release: https://github.com/$(gh repo view --json nameWithOwner -q .nameWithOwner)/releases/tag/$RELEASE_TAG"
echo ""
echo "Binaries uploaded:"
echo "  - chimera-linux (Linux x86_64)"
echo "  - chimera.exe (Windows x86_64)"
echo ""
echo "Next steps:"
echo "1. Update orchestrator.rs URLs to point to your release"
echo "2. Rebuild pandoras_box: cargo build --release --bin pandoras_box"
echo "3. Test deployment"
echo ""
