#!/bin/bash
# Convierte cada captura PCAP terminada en un CSV de flujos con CICFlowMeter
BASE="$(cd "$(dirname "$0")/../.." && pwd)"
PCAP_DIR="$BASE/Captures/PCAP"
CSV_DIR="$BASE/Captures/CSV"
CFM_HOME="$BASE/Topology/CICFlowMeter-4.0"
export CFM_OPTS="-Djava.library.path=$CFM_HOME/lib/native"

mkdir -p "$PCAP_DIR" "$CSV_DIR"
inotifywait -m -q -e close_write --format '%w%f' "$PCAP_DIR" | while read -r FILE
do
  "$CFM_HOME/bin/cfm" "$FILE" "$CSV_DIR/"
  echo "$FILE convertido a CSV por CICFlowMeter"
done
