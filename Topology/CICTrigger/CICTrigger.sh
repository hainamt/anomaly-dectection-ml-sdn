#!/bin/bash
# Convierte cada captura PCAP terminada en un CSV de flujos con CICFlowMeter
BASE="$(cd "$(dirname "$0")/../.." && pwd)"
PCAP_DIR="$BASE/Captures/PCAP"
CSV_DIR="$BASE/Captures/CSV"

mkdir -p "$PCAP_DIR" "$CSV_DIR"
inotifywait -m -q -e close_write --format '%w%f' "$PCAP_DIR" | while read -r FILE
do
  if "$BASE/Topology/CICTrigger/pcap2csv.sh" "$FILE" "$CSV_DIR"; then
    echo "$FILE convertido a CSV por CICFlowMeter"
  else
    echo "ERROR: no se pudo convertir $FILE" >&2
  fi
done
