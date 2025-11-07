#!/bin/bash
# Quick scan script for WebSec toolkit

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}"
cat << "EOF"
╦ ╦┌─┐┌┐ ╔═╗┌─┐┌─┐
║║║├┤ ├┴┐╚═╗├┤ │
╚╩╝└─┘└─┘╚═╝└─┘└─┘
Quick Scan Launcher
EOF
echo -e "${NC}"

# Check if target is provided
if [ $# -eq 0 ]; then
    echo -e "${RED}[!] Error: No target provided${NC}"
    echo -e "${YELLOW}Usage:${NC}"
    echo -e "  ${GREEN}./quick_scan.sh example.com${NC}           - Full recon"
    echo -e "  ${GREEN}./quick_scan.sh https://example.com -v${NC} - Full recon + vuln scan"
    exit 1
fi

TARGET=$1
VULN_SCAN=false

# Check if vulnerability scan is requested
if [ "$2" == "-v" ] || [ "$2" == "--vuln" ]; then
    VULN_SCAN=true
fi

# Create output directory
OUTPUT_DIR="results/$(echo $TARGET | sed 's/https\?:\/\///' | sed 's/\/.*$//')"
mkdir -p "$OUTPUT_DIR"

echo -e "${GREEN}[+] Target: ${NC}$TARGET"
echo -e "${GREEN}[+] Output: ${NC}$OUTPUT_DIR"
echo ""

# Run reconnaissance
echo -e "${BLUE}[*] Starting reconnaissance...${NC}"
python3 orchestrator/recon_runner.py -d "$TARGET" -o "$OUTPUT_DIR"

# Run vulnerability scan if requested
if [ "$VULN_SCAN" = true ]; then
    echo ""
    echo -e "${BLUE}[*] Starting vulnerability scan...${NC}"

    # Check if httpx results exist
    HTTPX_FILE="$OUTPUT_DIR/probes/httpx.txt"
    if [ -f "$HTTPX_FILE" ]; then
        # Scan all discovered URLs
        while IFS= read -r url; do
            echo -e "${YELLOW}[*] Scanning: $url${NC}"
            python3 orchestrator/vuln_scanner.py -u "$url" -o "$OUTPUT_DIR/vulns/$(echo $url | md5sum | cut -d' ' -f1)"
        done < "$HTTPX_FILE"
    else
        # Just scan the main target
        python3 orchestrator/vuln_scanner.py -u "https://$TARGET" -o "$OUTPUT_DIR/vulns"
    fi
fi

# Generate report
echo ""
echo -e "${BLUE}[*] Generating HTML report...${NC}"
python3 tools/utils/report_generator.py "$OUTPUT_DIR"

# Summary
echo ""
echo -e "${GREEN}╔════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║           SCAN COMPLETE                ║${NC}"
echo -e "${GREEN}╚════════════════════════════════════════╝${NC}"
echo ""
echo -e "${YELLOW}Results:${NC} $OUTPUT_DIR"
echo -e "${YELLOW}Report:${NC} $OUTPUT_DIR/report.html"
echo ""
echo -e "Open report: ${BLUE}firefox $OUTPUT_DIR/report.html${NC}"
echo ""
