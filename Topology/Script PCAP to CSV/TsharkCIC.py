"""Capture the switch ports in fixed windows and convert each PCAP to a CSV of flows.

Alternative to CICTrigger.sh + tshark. Run from the repo root as a user allowed
to capture (member of the wireshark group, or root):
    venv/bin/python "Topology/Script PCAP to CSV/TsharkCIC.py"
"""
import os
import subprocess
from datetime import datetime

import pyshark as ps

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
PCAP_DIR = os.path.join(BASE_DIR, 'Captures', 'PCAP')
CSV_DIR = os.path.join(BASE_DIR, 'Captures', 'CSV')
CFM_HOME = os.path.join(BASE_DIR, 'Topology', 'CICFlowMeter-4.0')
CAPTURE_SECONDS = 20

interfaces = ['s01-eth1', 's02-eth1', 's03-eth1', 's01-eth2', 's02-eth2', 's03-eth2']

os.makedirs(PCAP_DIR, exist_ok=True)
os.makedirs(CSV_DIR, exist_ok=True)
cfm_env = dict(os.environ, CFM_OPTS='-Djava.library.path=' + os.path.join(CFM_HOME, 'lib', 'native'))

index = 1
while True:
    # Same naming as a tshark ring buffer, which is what StartSupervisor looks for
    filename = os.path.join(PCAP_DIR, 'Flow_%05d_%s.pcap' % (index, datetime.now().strftime('%Y%m%d%H%M%S')))
    capture = ps.LiveCapture(interface=interfaces, output_file=filename)
    capture.sniff(timeout=CAPTURE_SECONDS)
    capture.close()

    # Convert in the background so the next window starts right away
    subprocess.Popen([os.path.join(CFM_HOME, 'bin', 'cfm'), filename, CSV_DIR + os.sep], env=cfm_env)
    index += 1
