#!/bin/bash
#
# test_external_tools.sh
#
# This script pulls tools from Stanford CCDC and Cal Poly Blue repositories
# and tests them to understand their functionality.
#
# WARNING: This downloads and runs binaries from external sources.
# Only run this in a safe, isolated environment (VM, container, etc.)
#
# Usage: ./scripts/test_external_tools.sh
#

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Create working directory
WORK_DIR="/tmp/ccdc_tool_testing"
mkdir -p "$WORK_DIR"
cd "$WORK_DIR"

echo -e "${BLUE}==================================================================${NC}"
echo -e "${BLUE}  CCDC External Tool Testing Suite${NC}"
echo -e "${BLUE}==================================================================${NC}"
echo ""
echo -e "${YELLOW}WARNING: This script downloads and tests binary executables${NC}"
echo -e "${YELLOW}from external repositories. Only run in an isolated environment.${NC}"
echo ""
read -p "Continue? (y/N) " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Aborted."
    exit 1
fi

# Function to print section headers
print_header() {
    echo ""
    echo -e "${GREEN}==================================================================${NC}"
    echo -e "${GREEN}  $1${NC}"
    echo -e "${GREEN}==================================================================${NC}"
    echo ""
}

# Function to test a binary
test_binary() {
    local binary_path="$1"
    local binary_name=$(basename "$binary_path")

    echo -e "${BLUE}Testing: $binary_name${NC}"
    echo "---"

    # Check if file exists
    if [ ! -f "$binary_path" ]; then
        echo -e "${RED}ERROR: Binary not found at $binary_path${NC}"
        return 1
    fi

    # File info
    echo -e "${YELLOW}File Type:${NC}"
    file "$binary_path"
    echo ""

    echo -e "${YELLOW}Size:${NC}"
    ls -lh "$binary_path" | awk '{print $5}'
    echo ""

    # Make executable
    chmod +x "$binary_path" 2>/dev/null || true

    # Try --help
    echo -e "${YELLOW}Testing --help flag:${NC}"
    if timeout 2 "$binary_path" --help 2>&1 | head -20; then
        echo ""
    else
        echo "(--help not supported or timed out)"
        echo ""
    fi

    # Try -h
    echo -e "${YELLOW}Testing -h flag:${NC}"
    if timeout 2 "$binary_path" -h 2>&1 | head -20; then
        echo ""
    else
        echo "(-h not supported or timed out)"
        echo ""
    fi

    # Try no args
    echo -e "${YELLOW}Testing with no arguments:${NC}"
    if timeout 2 "$binary_path" 2>&1 | head -20; then
        echo ""
    else
        echo "(No output or timed out)"
        echo ""
    fi

    # Extract interesting strings
    echo -e "${YELLOW}Interesting strings:${NC}"
    strings "$binary_path" | grep -iE "(usage|command|help|server|client|connect|listen|port|scan|map)" | head -20 || echo "(none found)"
    echo ""

    echo "---"
    echo ""
}

#=================================================================
# CLONE REPOSITORIES
#=================================================================

print_header "Cloning Repositories"

# Stanford CCDC
if [ ! -d "stanford-ccdc" ]; then
    echo "Cloning Stanford CCDC repository..."
    git clone --depth 1 https://github.com/applied-cyber/ccdc.git stanford-ccdc
else
    echo "Stanford CCDC already cloned"
fi

# Cal Poly Blue
if [ ! -d "cpp-cyber-blue" ]; then
    echo "Cloning Cal Poly Blue repository..."
    git clone --depth 1 https://github.com/cpp-cyber/blue.git cpp-cyber-blue
else
    echo "Cal Poly Blue already cloned"
fi

#=================================================================
# TEST GUMPER (Cal Poly)
#=================================================================

print_header "Testing Gumper (Cal Poly)"

echo -e "${BLUE}Gumper is a client-server tool with multiple platform binaries${NC}"
echo ""

# Test Linux version
if [ -f "cpp-cyber-blue/Linux/gumper/gumper-linux" ]; then
    test_binary "cpp-cyber-blue/Linux/gumper/gumper-linux"

    # Try to get more info
    echo -e "${YELLOW}Additional Analysis:${NC}"
    echo "Checking for Go runtime indicators..."
    if strings cpp-cyber-blue/Linux/gumper/gumper-linux | grep -q "go.build"; then
        echo "✓ Written in Go (confirmed)"
    fi

    echo ""
    echo "Checking for network functionality..."
    strings cpp-cyber-blue/Linux/gumper/gumper-linux | grep -iE "(tcp|udp|http|socket|dial|listen)" | head -10
    echo ""
fi

# Check Windows version
if [ -f "cpp-cyber-blue/Windows/bins/gumper.exe" ]; then
    echo -e "${YELLOW}Windows Version Info:${NC}"
    file cpp-cyber-blue/Windows/bins/gumper.exe
    ls -lh cpp-cyber-blue/Windows/bins/gumper.exe
    echo ""
fi

#=================================================================
# TEST BOXCRAB (Stanford)
#=================================================================

print_header "Testing Boxcrab (Stanford)"

echo -e "${BLUE}Boxcrab is a client-server system inventory dashboard${NC}"
echo ""

# Test server
if [ -f "stanford-ccdc/tools/boxcrab/binaries/boxcrab-server" ]; then
    echo -e "${GREEN}>>> Boxcrab Server${NC}"
    test_binary "stanford-ccdc/tools/boxcrab/binaries/boxcrab-server"
fi

# Test Linux client
if [ -f "stanford-ccdc/tools/boxcrab/binaries/boxcrab-client-linux-x64" ]; then
    echo -e "${GREEN}>>> Boxcrab Client (Linux x64)${NC}"
    test_binary "stanford-ccdc/tools/boxcrab/binaries/boxcrab-client-linux-x64"
fi

# Test ARM client
if [ -f "stanford-ccdc/tools/boxcrab/binaries/boxcrab-client-linux-arm64" ]; then
    echo -e "${GREEN}>>> Boxcrab Client (Linux ARM64)${NC}"
    file stanford-ccdc/tools/boxcrab/binaries/boxcrab-client-linux-arm64
    ls -lh stanford-ccdc/tools/boxcrab/binaries/boxcrab-client-linux-arm64
    echo ""
fi

# Test Windows client
if [ -f "stanford-ccdc/tools/boxcrab/binaries/boxcrab-client-windows-x64.exe" ]; then
    echo -e "${GREEN}>>> Boxcrab Client (Windows x64)${NC}"
    file stanford-ccdc/tools/boxcrab/binaries/boxcrab-client-windows-x64.exe
    ls -lh stanford-ccdc/tools/boxcrab/binaries/boxcrab-client-windows-x64.exe
    echo ""
fi

#=================================================================
# TEST CARTOGRAPHER (Stanford)
#=================================================================

print_header "Testing Cartographer (Stanford)"

echo -e "${BLUE}Cartographer appears to be a network scanning/mapping tool${NC}"
echo ""

# Test Linux version
if [ -f "stanford-ccdc/tools/cartographer/cartographerlp" ]; then
    echo -e "${GREEN}>>> Cartographer (Linux)${NC}"
    test_binary "stanford-ccdc/tools/cartographer/cartographerlp"
fi

# Test Windows version
if [ -f "stanford-ccdc/tools/cartographer/cartographerwp" ]; then
    echo -e "${GREEN}>>> Cartographer (Windows)${NC}"
    file stanford-ccdc/tools/cartographer/cartographerwp
    ls -lh stanford-ccdc/tools/cartographer/cartographerwp
    echo ""
fi

#=================================================================
# TEST PARSER (Stanford)
#=================================================================

print_header "Testing Parser (Stanford)"

echo -e "${BLUE}Parser is a Python-based nmap XML parser${NC}"
echo ""

if [ -d "stanford-ccdc/tools/parser" ]; then
    echo -e "${YELLOW}Parser Files:${NC}"
    ls -lh stanford-ccdc/tools/parser/
    echo ""

    echo -e "${YELLOW}Main Scripts:${NC}"
    for script in stanford-ccdc/tools/parser/*.py; do
        if [ -f "$script" ]; then
            echo "  - $(basename $script)"
            head -20 "$script" | grep -E "^(def |class |#)" || true
            echo ""
        fi
    done

    echo -e "${YELLOW}Testing nmap_parser.py:${NC}"
    if command -v python3 &> /dev/null; then
        cd stanford-ccdc/tools/parser
        python3 -c "import nmap_parser; help(nmap_parser.parse_file)" 2>&1 || echo "Could not import module"
        cd "$WORK_DIR"
    else
        echo "Python3 not available"
    fi
    echo ""
fi

#=================================================================
# TEST COORDINATE (Stanford vs Cal Poly comparison)
#=================================================================

print_header "Testing Coordinate (Comparison)"

echo -e "${BLUE}Coordinate is a Go-based SSH orchestration tool${NC}"
echo -e "${BLUE}Both Stanford and Cal Poly have versions${NC}"
echo ""

# Cal Poly version
if [ -f "cpp-cyber-blue/Linux/coordinate/coordinate.go" ]; then
    echo -e "${GREEN}>>> Cal Poly Coordinate (Source Available)${NC}"
    echo -e "${YELLOW}Source file info:${NC}"
    wc -l cpp-cyber-blue/Linux/coordinate/*.go
    echo ""

    echo -e "${YELLOW}Main features (from source):${NC}"
    grep -E "^(func |type )" cpp-cyber-blue/Linux/coordinate/coordinate.go | head -20
    echo ""
fi

# Stanford version
if [ -f "stanford-ccdc/tools/coordinate/coordinate.go" ]; then
    echo -e "${GREEN}>>> Stanford Coordinate (Source Available)${NC}"
    echo -e "${YELLOW}Source file info:${NC}"
    wc -l stanford-ccdc/tools/coordinate/*.go
    echo ""

    echo -e "${YELLOW}Comparing Cal Poly vs Stanford:${NC}"
    echo "Cal Poly lines: $(wc -l cpp-cyber-blue/Linux/coordinate/coordinate.go 2>/dev/null | awk '{print $1}')"
    echo "Stanford lines: $(wc -l stanford-ccdc/tools/coordinate/coordinate.go 2>/dev/null | awk '{print $1}')"
    echo ""

    if command -v diff &> /dev/null; then
        echo "Files are:"
        diff -q cpp-cyber-blue/Linux/coordinate/coordinate.go stanford-ccdc/tools/coordinate/coordinate.go && echo "  IDENTICAL" || echo "  DIFFERENT"
    fi
    echo ""
fi

#=================================================================
# ADVANCED TESTING (OPTIONAL)
#=================================================================

print_header "Advanced Testing (Optional)"

echo -e "${YELLOW}Would you like to attempt running the tools interactively?${NC}"
echo "This will attempt to start servers/clients to see their behavior."
echo ""
read -p "Run advanced tests? (y/N) " -n 1 -r
echo

if [[ $REPLY =~ ^[Yy]$ ]]; then

    # Test Boxcrab Server
    echo -e "${BLUE}Starting Boxcrab Server (will run for 5 seconds)...${NC}"
    if [ -f "stanford-ccdc/tools/boxcrab/binaries/boxcrab-server" ]; then
        chmod +x stanford-ccdc/tools/boxcrab/binaries/boxcrab-server
        timeout 5 stanford-ccdc/tools/boxcrab/binaries/boxcrab-server \
            -server-listen-address "127.0.0.1:18080" \
            2>&1 | head -50 &
        SERVER_PID=$!

        sleep 2

        # Try to connect
        echo ""
        echo -e "${YELLOW}Attempting to connect to Boxcrab web interface...${NC}"
        curl -v http://127.0.0.1:18080 2>&1 | head -30 || echo "Connection failed"

        # Kill server
        kill $SERVER_PID 2>/dev/null || true
        wait $SERVER_PID 2>/dev/null || true
        echo ""
    fi

    echo -e "${BLUE}Done with advanced testing${NC}"
fi

#=================================================================
# GENERATE REPORT
#=================================================================

print_header "Generating Report"

REPORT_FILE="$WORK_DIR/tool_analysis_report.txt"

cat > "$REPORT_FILE" << 'EOF'
CCDC External Tool Analysis Report
Generated: $(date)

This report contains findings from testing binaries from:
- Stanford CCDC: https://github.com/applied-cyber/ccdc
- Cal Poly Blue: https://github.com/cpp-cyber/blue

=================================================================
FINDINGS SUMMARY
=================================================================

1. GUMPER (Cal Poly)
   - Type: Client-server remote access agent
   - Language: Go
   - Platforms: Linux, FreeBSD, DragonFly, Windows
   - Size: 9-13MB (statically linked)
   - Usage: ./gumper-linux -server <IP>
   - Purpose: Reverse connection agent for remote command execution
   - Confidence: HIGH (confirmed from help output)

2. BOXCRAB (Stanford)
   - Type: System inventory dashboard
   - Language: Go (likely)
   - Platforms: Linux (x64, ARM64), Windows
   - Size: 17-40MB
   - Usage:
     Server: ./boxcrab-server -server-listen-address ":8080"
     Client: ./boxcrab-client-linux-x64
   - Purpose: Web-based system inventory visualization
   - Confidence: HIGH (confirmed from detailed help output)

3. CARTOGRAPHER (Stanford)
   - Type: Network scanner/mapper
   - Language: Unknown (statically linked, stripped binary)
   - Platforms: Linux, Windows
   - Size: 4MB
   - Usage: Unknown (help not available)
   - Purpose: Network scanning with configurable delay
   - Confidence: LOW (minimal information, mostly inferred)

4. PARSER (Stanford)
   - Type: Nmap XML parser
   - Language: Python
   - Platforms: Any (Python)
   - Size: <10KB
   - Usage: python3 parse_and_plot.py <nmap_xml>
   - Purpose: Parse nmap results, generate diagrams and CSV
   - Confidence: VERY HIGH (source code available)

5. COORDINATE (Both Repos)
   - Type: SSH orchestration tool
   - Language: Go
   - Source: Available in both repos
   - Purpose: Multi-host SSH command execution with tmux
   - Confidence: VERY HIGH (source code available)

=================================================================
RECOMMENDATIONS
=================================================================

HIGH VALUE TOOLS:
- Parser (Stanford) - Essential for nmap result processing
- Boxcrab (Stanford) - Excellent for real-time system inventory
- Coordinate (Both) - Primary Linux control tool
- Gumper (Cal Poly) - Useful fallback for firewalled hosts

MEDIUM VALUE TOOLS:
- Cartographer (Stanford) - Useful if you need simple scanning

INTEGRATION STRATEGY:
1. Use Pandora's Box for initial deployment
2. Deploy Boxcrab clients for monitoring
3. Use Coordinate for interactive control
4. Deploy Gumper to firewalled hosts as fallback
5. Use Parser for all network scans

=================================================================
EOF

echo "$REPORT_FILE created with findings summary"
echo ""
echo -e "${GREEN}Testing complete!${NC}"
echo ""
echo -e "${YELLOW}Report saved to: $REPORT_FILE${NC}"
echo -e "${YELLOW}Tools cloned to: $WORK_DIR${NC}"
echo ""
echo -e "${BLUE}To clean up:${NC} rm -rf $WORK_DIR"
echo ""
