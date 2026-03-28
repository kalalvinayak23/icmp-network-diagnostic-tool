# ICMP Network Diagnostic Tool

## Problem Statement
To analyze network performance using ICMP (ping and traceroute) and visualize the output using a dashboard.

## Architecture
C ICMP Tool → Output Files → Dashboard Parser → Visualization

## Features
- Ping (RTT, packet loss)
- Traceroute (hop-by-hop path)
- Dashboard visualization
- Raw output display

## How to Run

1. Compile:
gcc icmp_diag.c -o icmp_diag

2. Run:
sudo ./icmp_diag ping google.com > ping_output.txt
sudo ./icmp_diag traceroute google.com > traceroute_output.txt

Make sure ping_output.txt and traceroute_output.txt are present in the same folder as dashboard.html.

4. Start server:
python3 -m http.server 8000

5. Open:
http://localhost:8000/dashboard.html

## Output
- RTT graph
- Packet loss
- Traceroute hops
- Raw terminal output

## Future Improvements
- Real-time execution
- Live monitoring dashboard
