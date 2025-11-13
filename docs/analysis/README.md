# CCDC Tool Analysis Documentation

This directory contains comprehensive analysis of CCDC competition toolkits.

## Documents

### 1. CCDC_TACTICAL_GUIDE.md
**50-page comprehensive tactical guide** comparing three major CCDC toolkits:
- Pandora's Box (this repository)
- Cal Poly Blue Team toolkit
- Stanford CCDC toolkit

**Contents**:
- Complete tool matrix (what each tool does)
- Hour-by-hour tactical timeline
- Strategic deployment recommendations
- Scenario-based tool selection guide
- Pro tips from competition winners

**Key Question Answered**: Is Pandora's Box worth using?

**TL;DR**: Yes for Hour 0 mass deployment. Use in combination with:
- Geist (Stanford) for fastest initial deployment
- Coordinate (Cal Poly) for interactive Linux control
- Boxcrab (Stanford) for real-time monitoring dashboard
- Ansible (Stanford) for declarative automation

---

### 2. UNKNOWN_TOOLS_ANALYSIS.md
**Deep dive into previously undocumented tools** found in external repos:

**Tools Analyzed**:
1. **Gumper** (Cal Poly) - Client-server remote access agent
2. **Boxcrab** (Stanford) - System inventory visualization dashboard
3. **Cartographer** (Stanford) - Network scanning/mapping tool
4. **Parser** (Stanford) - Nmap XML parser

**Analysis Method**:
- Binary reverse engineering
- String extraction
- Help flag testing
- Source code review (where available)

**Confidence Levels**:
- ✅ **HIGH**: Parser, Boxcrab, Gumper (confirmed functionality)
- ⚠️ **MEDIUM**: Cartographer (limited information)

**Honesty Disclaimer**: Some functionality is inferred from binary analysis, not confirmed through actual deployment testing.

---

## Testing These Tools

To pull and test the external tools yourself:

```bash
# Run the testing script
./scripts/test_external_tools.sh
```

This script will:
1. Clone Stanford and Cal Poly repositories
2. Extract all binaries
3. Test with `--help`, `-h`, and no arguments
4. Extract interesting strings
5. Generate a detailed report

**WARNING**: Only run in an isolated environment (VM, container, etc.) as it downloads and tests external binaries.

---

## Key Findings

### The Winning CCDC Stack

```
Hour 0 (0-15 min): Pandora's Box
  └─ Fastest: enumerate + connect + deploy in one command

Hour 1 (15-60 min): Boxcrab + Coordinate
  └─ Real-time monitoring + interactive control

Hour 2+ (60+ min): Ansible + ELK
  └─ Declarative automation + deep log analysis

Fallback: Gumper
  └─ Reverse connection agent for firewalled hosts
```

### Tool Recommendations by Purpose

**Fastest Deployment**: Pandora's Box, then Geist
**Interactive Control**: Coordinate (Cal Poly)
**Monitoring Dashboard**: Boxcrab (Stanford)
**Automation**: Ansible (Stanford)
**Log Analysis**: ELK Stack (Cal Poly)
**Firewall Bypass**: Gumper (Cal Poly)
**Network Scanning**: Cartographer or Nmap + Parser (Stanford)

---

## Document Accuracy

### What is CONFIRMED
- Parser functionality (have source code)
- Boxcrab server flags and purpose (detailed help output)
- Gumper client-server architecture (help output + strings)
- All Pandora's Box functionality (this repo)
- Coordinate functionality (source available in both repos)

### What is INFERRED
- Boxcrab dashboard contents (guessed from "system-inventory" API)
- Cartographer scanning behavior (guessed from "Scan delay" string)
- Gumper protocol details (assumed reverse connection)

### What is UNKNOWN
- Cartographer exact usage and output format
- Boxcrab API endpoint implementation details
- Gumper server component location/implementation

---

## How to Use These Docs

1. **Start with CCDC_TACTICAL_GUIDE.md**
   - Read Executive Summary for quick overview
   - Jump to "Part 2: Tactical Timeline" for hour-by-hour strategy
   - Use "Part 6: Scenario-Based Recommendations" for your specific situation

2. **Consult UNKNOWN_TOOLS_ANALYSIS.md**
   - When you encounter Gumper, Boxcrab, or Cartographer
   - To understand integration with Pandora's Box
   - For tool comparison matrices

3. **Run the test script**
   - To verify findings on your own system
   - To get hands-on experience with the tools
   - To generate a fresh analysis report

---

## Contributing

If you test these tools and discover additional functionality:

1. Update the relevant markdown file
2. Add your findings with confidence level (HIGH/MEDIUM/LOW)
3. Include evidence (screenshots, help output, etc.)
4. Submit a PR or issue

**Especially valuable**:
- Actual deployment testing of Gumper
- Boxcrab dashboard screenshots
- Cartographer usage examples
- Any tool we missed

---

## Credits

**Analysis by**: Claude (AI) + M00NLIG7 (verification)

**Sources**:
- Pandora's Box: https://github.com/M00NLIG7/pandoras_box
- Cal Poly Blue: https://github.com/cpp-cyber/blue
- Stanford CCDC: https://github.com/applied-cyber/ccdc

**Date**: November 2025

**License**: Same as parent repository (see LICENSE)

---

## Quick Reference

### One-Line Tool Descriptions

| Tool | One-Liner |
|------|-----------|
| **Pandora's Box** | Rust orchestrator: enumerate → connect → deploy → execute → collect |
| **Gumper** | Go client-server agent with reverse connections |
| **Boxcrab** | Real-time system inventory web dashboard |
| **Cartographer** | Network scanner with configurable delay |
| **Parser** | Python nmap XML → diagrams + CSV |
| **Coordinate** | Go SSH orchestrator with tmux integration |
| **Geist** | Bash/PowerShell one-liner mass deployment |
| **Ansible** | Declarative infrastructure automation |

### When to Use What

- **Need to deploy NOW**: Pandora's Box or Geist
- **Need interactive shells**: Coordinate
- **Need monitoring**: Boxcrab or ELK
- **Need automation**: Ansible
- **Firewall bypass needed**: Gumper
- **Network discovery**: Cartographer or Nmap + Parser
- **Windows-heavy environment**: Pandora's Box (WinRM support)

---

*Last Updated: 2025-11-13*
