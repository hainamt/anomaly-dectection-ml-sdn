#!/bin/bash
# Usage: pcap2csv.sh <capture.pcap> <csv_dir>
# Converts one capture to a CSV of flows with CICFlowMeter, named <capture>.pcap_Flow.csv.
#
# Before converting, the packets are sorted by timestamp and the file is rewritten as
# classic pcap:
#  - A capture on several interfaces is written in per-interface blocks, not in time
#    order. CICFlowMeter assumes time order; otherwise it splits connections into
#    flows with negative durations, and the model misses most of an attack.
#  - CICFlowMeter rejects some pcapng files ("Please select pcap file!").
set -e
FILE="$1"
CSV_DIR="$2"
CFM_HOME="$(cd "$(dirname "$0")/../CICFlowMeter-4.0" && pwd)"
export CFM_OPTS="-Djava.library.path=$CFM_HOME/lib/native"

# Same base name as the capture, so the CSV keeps the name the Supervisor looks for.
# The folder is next to the captures (not /tmp, which may be too small) and is not
# watched by CICTrigger, which only watches the captures folder itself.
WORK="$(mktemp -d "$(dirname "$FILE")/.pcap2csv.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
NAME="$(basename "$FILE")"

reordercap "$FILE" "$WORK/sorted" > /dev/null
editcap -F pcap "$WORK/sorted" "$WORK/$NAME"
"$CFM_HOME/bin/cfm" "$WORK/$NAME" "$CSV_DIR/"
