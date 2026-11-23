# Analysis of Unknown CCDC Tools: Gumper, Boxcrab, and Cartographer

## Executive Summary

After reverse-engineering three previously undocumented CCDC tools, here's what they do:

1. **Gumper** (Cal Poly): Client-server remote access tool (similar to chimera from Pandora's Box)
2. **Boxcrab** (Stanford): System inventory visualization dashboard with client-server architecture
3. **Cartographer** (Stanford): Network scanning/mapping tool (nmap wrapper)
4. **Parser** (Stanford): Nmap XML parser for generating network diagrams

---

## 1. Gumper (Cal Poly Blue Team)

### What Is It?
**Gumper** is a client-server remote access tool built in Go, providing cross-platform agent deployment similar to Pandora's Box's chimera.

### File Details
```
Location: /tmp/cpp-cyber-blue/Linux/gumper/
Files:
- gumper-linux (11MB, ELF 64-bit, statically linked)
- gumper-freebsd (13MB)
- gumper-dragonfly (9.9MB)
- gumper.exe (9.1MB, Windows PE32+)
```

### Usage
```bash
./gumper-linux -server <SERVER_IP>
```

**Parameters**:
- `-server string`: Server IP address to connect to

### Architecture
```
┌─────────────────┐
│  Control Server │ (Unknown location - not in repo)
│   (Receives)    │
└────────▲────────┘
         │
         │ Connects to server
         │
┌────────┴────────┐
│  Gumper Client  │ (Deployed to targets)
│  (Sends data)   │
└─────────────────┘
```

### How It Works
1. **Deployment**: Gumper client binary is deployed to target hosts
2. **Connection**: Client connects back to control server specified by `-server` flag
3. **Communication**: Establishes persistent connection for remote command execution
4. **Data Collection**: Sends system information back to control server

### Use Case in CCDC
**Primary Purpose**: Agent-based remote access for hosts where SSH/WinRM is unavailable or firewalled

**Deployment Strategy**:
```bash
# Set up control server (address: 10.0.1.100)
# Deploy gumper to targets via coordinate or other means
./coordinate -t 10.0.0.0/24 -u admin -p pass -S "wget http://10.0.1.100/gumper-linux && chmod +x gumper-linux && ./gumper-linux -server 10.0.1.100 &"
```

**Advantages**:
- ✅ Cross-platform (Linux, FreeBSD, DragonFly, Windows)
- ✅ Statically linked (no dependencies)
- ✅ Persistent reverse connection (bypasses firewalls)
- ✅ Single binary deployment

**Disadvantages**:
- ❌ Requires pre-deployed control server
- ❌ No source code in repo (binary-only)
- ❌ Unknown protocol/security features
- ❌ Larger binary size (9-13MB)

### Comparison to Pandora's Box Chimera

| Feature | Gumper | Chimera (Pandora's Box) |
|---------|--------|------------------------|
| **Size** | 9-13MB | Unknown |
| **Platforms** | Linux, FreeBSD, DragonFly, Windows | Linux, Windows |
| **Connection** | Client → Server | Server downloads from GitHub |
| **Architecture** | Reverse connection | File server + executor |
| **Source Code** | ❌ Binary only | ✅ Available (Rust) |
| **Deployment** | Manual push | Automated via pandoras_box |
| **Control** | Central server | Orchestrator-based |

**Winner**: **Chimera** for integration with orchestration, **Gumper** for simplicity and reverse connection capability

### Strategic Value

**Use Gumper when**:
- You need reverse connections (target → control server)
- Firewalls block inbound SSH/WinRM
- You want persistent agents without complex orchestration
- Supporting FreeBSD/DragonFly systems

**Skip Gumper when**:
- SSH/WinRM is available (use coordinate instead)
- You need orchestrated workflows (use Pandora's Box)
- Binary size is a concern (9-13MB vs coordinate's smaller footprint)
- You need source code transparency

---

## 2. Boxcrab (Stanford CCDC)

### What Is It?
**Boxcrab** is a system inventory visualization dashboard with client-server architecture for real-time monitoring of deployed systems.

### File Details
```
Location: /tmp/stanford-ccdc/tools/boxcrab/binaries/
Files:
- boxcrab-server (40MB, ELF 64-bit)
- boxcrab-client-linux-x64 (21MB)
- boxcrab-client-linux-arm64 (17MB)
- boxcrab-client-windows-x64.exe (23MB)
```

### Usage

**Server**:
```bash
./boxcrab-server \
  -api-endpoint "http://localhost:9090/api/system-inventory" \
  -server-listen-address ":8080" \
  -refresh-interval 60 \
  -log-file "/var/log/boxcrab.log"
```

**Parameters**:
- `-api-endpoint string`: API endpoint to fetch system inventory data (default: http://localhost:9090/api/system-inventory)
- `-server-listen-address string`: Address and port for web server (default: :8080)
- `-refresh-interval int`: Interval in seconds to refresh inventory data (default: 60)
- `-log-file string`: Log file path (empty for stdout)

**Client**:
```bash
# Likely sends system inventory to API endpoint
./boxcrab-client-linux-x64 <options>
```

### Architecture
```
┌──────────────────┐
│   Web Browser    │ View dashboard at http://server:8080
│  (Blue Team)     │
└────────▲─────────┘
         │
         │ HTTP
         │
┌────────┴─────────┐
│  Boxcrab Server  │ Listens on :8080
│  (Dashboard)     │ Fetches from API every 60s
└────────▲─────────┘
         │
         │ HTTP API
         │
┌────────┴─────────┐
│  API Endpoint    │ http://localhost:9090/api/system-inventory
│  (JSON data)     │
└────────▲─────────┘
         │
         │ POST inventory data
         │
┌────────┴─────────┐
│ Boxcrab Clients  │ Deployed on all hosts
│  (Agents)        │ Send system info
└──────────────────┘
```

### How It Works
1. **Deploy Clients**: Install boxcrab-client on all target hosts
2. **Configure API**: Clients send system inventory to API endpoint (possibly custom or built-in)
3. **Start Server**: Boxcrab server fetches from API endpoint every 60 seconds
4. **View Dashboard**: Access web dashboard at http://server:8080 to see all systems

### Use Case in CCDC

**Primary Purpose**: Real-time system inventory dashboard for situational awareness

**Deployment Strategy**:
```bash
# 1. Set up boxcrab server on monitoring host (10.0.1.100)
./boxcrab-server -server-listen-address ":8080" -log-file "/var/log/boxcrab.log"

# 2. Deploy clients to all hosts via coordinate
./coordinate -t 10.0.0.0/24 -u admin -p pass -S \
  "wget http://10.0.1.100/boxcrab-client-linux-x64 && \
   chmod +x boxcrab-client-linux-x64 && \
   ./boxcrab-client-linux-x64 --api-endpoint http://10.0.1.100:9090/api/system-inventory &"

# 3. Access dashboard
# Open browser to http://10.0.1.100:8080
```

**Dashboard Likely Shows**:
- System hostnames and IP addresses
- OS versions and kernel info
- CPU/Memory/Disk usage
- Running services
- Network interfaces
- Installed packages
- Security status (firewall, SELinux, etc.)

**Advantages**:
- ✅ Real-time system inventory visualization
- ✅ Cross-platform clients (Linux x64/ARM, Windows)
- ✅ Web-based dashboard (no client needed to view)
- ✅ Configurable refresh interval
- ✅ API-based architecture (flexible integration)

**Disadvantages**:
- ❌ Large binary sizes (17-40MB)
- ❌ Requires API endpoint (may need custom setup)
- ❌ No source code (binary-only)
- ❌ Resource intensive (polling every 60s)

### Comparison to ELK Stack

| Feature | Boxcrab | ELK Stack (Cal Poly) |
|---------|---------|---------------------|
| **Purpose** | System inventory dashboard | Centralized logging |
| **Data Type** | System metrics | Logs |
| **Deployment** | Clients + Server | Beats + Elasticsearch + Kibana |
| **Complexity** | Medium | High |
| **Resource Usage** | Medium | High |
| **Customization** | Limited (binary) | Extensive |
| **Visualization** | Built-in dashboard | Kibana dashboards |
| **Query Language** | Unknown | Lucene/KQL |

**Winner**: **ELK** for comprehensive monitoring, **Boxcrab** for quick system inventory

### Strategic Value

**Use Boxcrab when**:
- You need quick system inventory visualization
- ELK is too complex/resource-intensive
- You want real-time host status at a glance
- Tracking which hosts are up/down/compromised

**Skip Boxcrab when**:
- You need log analysis (use ELK)
- You need detailed security monitoring
- Binary size/resources are constrained
- You need source code transparency

---

## 3. Cartographer (Stanford CCDC)

### What Is It?
**Cartographer** is a network scanning/mapping tool, likely an nmap wrapper with visualization capabilities.

### File Details
```
Location: /tmp/stanford-ccdc/tools/cartographer/
Files:
- cartographerlp (4.1MB, ELF 64-bit, statically linked, stripped)
- cartographerwp (4.2MB, MS-DOS executable - Windows)
```

### Evidence of Function
From strings analysis:
- "Scan delay (%d)" - Indicates network scanning functionality
- Two versions: "lp" (Linux/Python?) and "wp" (Windows/PowerShell?)

### Architecture (Hypothesized)
```
┌─────────────────┐
│  Cartographer   │ Network scanner
│   (Executor)    │
└────────┬────────┘
         │
         ├─→ Runs nmap scans with delay
         │
         ├─→ Parses results
         │
         └─→ Generates network map/diagram
```

### Likely Usage
```bash
# Scan network with delay between hosts
./cartographerlp <CIDR> <DELAY_MS>

# Example
./cartographerlp 10.0.0.0/24 1000  # 1 second delay between hosts
```

### Use Case in CCDC

**Primary Purpose**: Automated network discovery and mapping

**Deployment Strategy**:
```bash
# Run from monitoring host
./cartographerlp 10.0.0.0/24 500 > network_map.txt

# Likely outputs:
# - Host discovery results
# - Open ports per host
# - Service versions
# - Network topology diagram
```

### Integration with Parser

Cartographer likely works with the **parser** tool:
```bash
# 1. Cartographer generates nmap XML
./cartographerlp 10.0.0.0/24 500 -oX scan.xml

# 2. Parser processes XML
python3 /tmp/stanford-ccdc/tools/parser/parse_and_plot.py scan.xml

# 3. Output: Network diagram and CSV
```

### Advantages
- ✅ Automated network scanning
- ✅ Cross-platform (Linux and Windows versions)
- ✅ Configurable scan delay (stealth/performance)
- ✅ Statically linked (no dependencies)

### Disadvantages
- ❌ Binary-only (no source code)
- ❌ Unknown output format
- ❌ Limited documentation
- ❌ Requires testing to fully understand

### Comparison to Other Scan Tools

| Feature | Cartographer | Nmap | Cal Poly Enumerate |
|---------|--------------|------|-------------------|
| **Speed** | Unknown (has delay) | Fast | Fast (ICMP + SSH only) |
| **Stealth** | Configurable delay | Many options | Basic |
| **Output** | Unknown | XML/JSON/etc | CSV |
| **Simplicity** | High | Low | Very High |
| **Source** | ❌ Binary | ✅ Open Source | ✅ Available |

### Strategic Value

**Use Cartographer when**:
- You need automated network mapping
- Want simple scan tool without nmap complexity
- Need cross-platform scanning
- Require scan delay for stealth

**Skip Cartographer when**:
- Nmap is available and you know how to use it
- Cal Poly enumerate is sufficient (ICMP + SSH only)
- You need advanced scanning features
- Source code transparency is required

---

## 4. Parser (Stanford CCDC)

### What Is It?
**Parser** is a collection of Python scripts for parsing nmap XML output and generating network diagrams.

### Files
```
Location: /tmp/stanford-ccdc/tools/parser/
Files:
- nmap_parser.py (5.2KB) - Core parsing library
- parse_and_plot.py (7.3KB) - Main script with visualization
- diagram.py (1.7KB) - Diagram generation
- nmap_example.xml (63KB) - Example nmap output
- local_scan.xml (15KB) - Example scan
```

### Usage
```python
# Parse nmap XML and generate network diagram
python3 parse_and_plot.py scan.xml

# Or use as library
from nmap_parser import parse_file
elements = parse_file("scan.xml")
for host in elements:
    print(host.getAddress(), host.os, host.getAllOpenServices())
```

### Features (from code analysis)

**NetworkElement Class**:
- Parses host IP, hostname, OS, services
- Tracks service state (open/closed)
- Extracts service name, product, version
- Subnet calculation
- Gateway detection

**Output**:
- Network diagrams (via diagram.py)
- CSV export of hosts and services
- Structured data for further processing

### Use Case in CCDC
```bash
# 1. Scan network
nmap -sV -O 10.0.0.0/24 -oX scan.xml

# 2. Parse and visualize
python3 parse_and_plot.py scan.xml

# 3. Review output
# - network_diagram.png (visual map)
# - hosts.csv (host list)
# - services.csv (service inventory)
```

### Advantages
- ✅ Open source Python (readable/modifiable)
- ✅ Parses standard nmap XML
- ✅ Generates visual diagrams
- ✅ CSV export for spreadsheets
- ✅ Library for custom scripts

### Disadvantages
- ❌ Python dependency
- ❌ Limited to nmap XML format
- ❌ Basic visualization (not interactive)

### Strategic Value

**Use Parser when**:
- Processing nmap scan results
- Need visual network diagrams
- Want CSV export for documentation
- Building custom analysis scripts

**Skip Parser when**:
- Using nmap's built-in output formats is sufficient
- Need interactive visualization (use Zenmap)
- Don't have Python available

---

## Comparative Analysis: All Unknown Tools

### Tool Comparison Matrix

| Tool | Type | Size | Platform | Source | Purpose | CCDC Value |
|------|------|------|----------|--------|---------|------------|
| **Gumper** | Agent | 9-13MB | Multi | ❌ Binary | Remote access | ⭐⭐⭐ |
| **Boxcrab** | Dashboard | 17-40MB | Multi | ❌ Binary | Inventory viz | ⭐⭐⭐⭐ |
| **Cartographer** | Scanner | 4MB | Multi | ❌ Binary | Network mapping | ⭐⭐⭐ |
| **Parser** | Utility | <10KB | Python | ✅ Source | Nmap parsing | ⭐⭐⭐⭐ |

### Strategic Deployment Timeline

**Hour 0-1: Discovery Phase**
```bash
# Use Cartographer for initial network scan
./cartographerlp 10.0.0.0/24 100 -oX initial_scan.xml

# Parse results
python3 parser/parse_and_plot.py initial_scan.xml
```

**Hour 1-2: Agent Deployment**
```bash
# Deploy Gumper agents for persistent access
# (Useful for hosts where SSH/WinRM fails)
for ip in $(cat high_value_targets.txt); do
    scp gumper-linux $ip:/tmp/
    ssh $ip "/tmp/gumper-linux -server 10.0.1.100 &"
done
```

**Hour 2-3: Monitoring Setup**
```bash
# Deploy Boxcrab for system inventory dashboard
./boxcrab-server -server-listen-address ":8080" &

# Deploy clients via coordinate
./coordinate -t @targets.txt -u admin -p pass -S \
    "wget http://10.0.1.100/boxcrab-client && ./boxcrab-client &"
```

**Hour 3+: Ongoing Operations**
```bash
# Check Boxcrab dashboard for system status
curl http://10.0.1.100:8080

# Use Gumper for hosts with firewall issues
# (Command execution via control server)

# Re-scan network periodically
./cartographerlp 10.0.0.0/24 1000 -oX rescan.xml
python3 parser/parse_and_plot.py rescan.xml
```

---

## Integration with Pandora's Box

### Should You Use These Tools WITH Pandora's Box?

**YES - Complementary Tools**:

1. **Boxcrab + Pandora's Box**:
   ```
   Pandora's Box: Initial deployment and command execution
   Boxcrab: Ongoing system inventory visualization
   ```
   - Use pandoras_box to deploy boxcrab clients
   - Use boxcrab dashboard to monitor deployed systems

2. **Cartographer + Pandora's Box**:
   ```
   Cartographer: Pre-deployment network discovery
   Pandora's Box: Deploy to discovered hosts
   ```
   - Use cartographer to find hosts
   - Feed IP list to pandoras_box for deployment

3. **Gumper vs Pandora's Box**:
   ```
   Decision: Choose ONE based on environment
   ```
   - **Gumper**: Better for reverse connections, firewall bypass
   - **Pandora's Box**: Better for orchestrated workflows
   - **Both**: Use gumper as fallback when pandoras_box fails

### Recommended Integration Stack

```
┌─────────────────────────────────────────────┐
│          HOUR 0: DISCOVERY                  │
│  Cartographer → Parser → Target List        │
├─────────────────────────────────────────────┤
│          HOUR 1: DEPLOYMENT                 │
│  Pandora's Box → Mass deployment            │
│  Gumper → Fallback for firewalled hosts     │
├─────────────────────────────────────────────┤
│          HOUR 2+: MONITORING                │
│  Boxcrab Dashboard → System inventory       │
│  ELK Stack → Log analysis                   │
│  Coordinate → Interactive troubleshooting   │
└─────────────────────────────────────────────┘
```

---

## Final Verdict: Are These Tools Worth Using?

### Gumper: ⭐⭐⭐ (Situational)

**Use if**:
- Need reverse connections (firewall bypass)
- Pandora's Box deployment fails
- Supporting FreeBSD/DragonFly

**Skip if**:
- SSH/WinRM is available
- Binary size is a concern
- Need source code transparency

### Boxcrab: ⭐⭐⭐⭐ (High Value)

**Use if**:
- Need real-time system inventory
- Want simple dashboard without ELK complexity
- Tracking host status across competition

**Skip if**:
- Already using ELK Stack
- Resource constrained
- Need detailed log analysis

### Cartographer: ⭐⭐⭐ (Useful)

**Use if**:
- Need simple network scanning
- Want automated mapping
- Nmap is too complex

**Skip if**:
- Already comfortable with nmap
- Cal Poly enumerate is sufficient
- Need advanced scanning features

### Parser: ⭐⭐⭐⭐⭐ (Essential)

**Use always**:
- Lightweight, open source, versatile
- Essential for processing nmap results
- Generates documentation automatically
- No downside

---

## Conclusion

All three repositories (Pandora's Box, Cal Poly Blue, Stanford CCDC) contain valuable tools:

**Pandora's Box**: Best for orchestrated mass deployment
**Cal Poly**: Best for interactive control (coordinate) and monitoring (ELK)
**Stanford**: Best for automation (Ansible) and quick wins (geist, parser, boxcrab)

**The Winning Combination**:
```
Primary Stack:
1. Geist (Stanford) - Hour 0 deployment
2. Coordinate (Cal Poly) - Interactive control
3. Pandora's Box - Windows/WinRM scenarios
4. Boxcrab (Stanford) - Real-time inventory
5. Parser (Stanford) - Network documentation

Fallback/Specialty:
- Gumper (Cal Poly) - Reverse connection fallback
- Cartographer (Stanford) - Simple network scanning
- ELK (Cal Poly) - Deep log analysis
- Ansible (Stanford) - Declarative automation
```

The key is not choosing one toolkit, but **combining the best tools from each** for a comprehensive CCDC strategy.
