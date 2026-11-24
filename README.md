# Anomaly Detection ML-SDN-based

![Topology](https://user-images.githubusercontent.com/84791557/132374979-7656ab1b-baab-4ead-ba1f-72405f73b5a7.png)

## Tools
- Mininet- Network Topology Simulator, can be use via Python API: http://mininet.org/download/
- Ryu SDN Controller: https://github.com/faucetsdn/ryu
- Wireshark-Packet Capture and export PCAP files: https://www.wireshark.org/download.html
- MongoDB to store Topology's information: https://www.mongodb.com/try/download/community 
- CICFlowMeter-Feature Extractor from PCAP files and export CSV files: https://github.com/ahlashkari/CICFlowMeter

## Environment setting
The steps below were tested on a single Ubuntu 24.04 machine, with Mininet, Ryu, MongoDB and the Supervisor all on one host. The original setup used two VirtualBox VMs (a Mininet server and a controller server) with a shared folder for the CSV files. That still works if you point the controller IP and the CSV folder at the other VM.

### 1. System packages
```
sudo add-apt-repository ppa:deadsnakes/ppa      # Python 3.9 is not in the Ubuntu 24.04 repos
sudo apt install python3.9 python3.9-venv mininet openvswitch-switch \
                 tshark inotify-tools libpcap-dev openjdk-21-jre
```
Install MongoDB Community from https://www.mongodb.com/docs/manual/administration/install-on-linux/ and start it (`sudo systemctl start mongod`). Optional, for generating traffic: `sudo apt install iperf hping3`.

### 2. Python environment
The trained models (`Models/*.pkl`) and the data pipeline were saved with scikit-learn 0.24.2, which only supports Python 3.6–3.9, so use a Python 3.9 virtualenv with the pinned versions:
```
python3.9 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```
Keep `eventlet==0.30.2`: Ryu 4.34 imports `eventlet.wsgi.ALREADY_HANDLED`, which was removed in eventlet 0.30.3.

### 3. Run
Each command in its own terminal, from the repository root, with the venv activated where Python is used. Runtime files go to `Captures/PCAP` and `Captures/CSV`.

1. Controller (Ryu + topology to MongoDB + REST API on port 8080):
```
cd Controller && ryu-manager --observe-links --verbose Topo_to_Mongo.py ofctl_rest.py
```
2. Topology (3 switches, 6 hosts `10.0.0.11`–`10.0.0.16`):
```
cd Topology && sudo mn --custom SplTp.py --topo Simple_Topo --controller=remote,ip=127.0.0.1
```
3. PCAP to CSV converter (start it before the capture: it creates `Captures/PCAP` and `Captures/CSV`). For each finished capture, `pcap2csv.sh` sorts the packets by time with `reordercap`, rewrites the file as classic pcap with `editcap` (both come with tshark) and runs CICFlowMeter. A capture on several interfaces is not in time order. Unsorted, CICFlowMeter starts some flows at the reply instead of the request: in a test hping3 attack from h02 to h06, 366 flows were attributed to the victim, flagged as anomalies, and h06 was blocked along with the attacker.
```
./Topology/CICTrigger/CICTrigger.sh
```
4. Capture the host-facing switch ports in 30 s ring-buffer files (tshark names them `Flow_{index}_{timestamp}.pcap`). Run it as your user, not with sudo: members of the `wireshark` group can capture, and as root tshark failed to create the files.
```
tshark -f "ip and inbound" -i s01-eth1 -i s01-eth2 -i s02-eth1 -i s02-eth2 -i s03-eth1 -i s03-eth2 \
       -b duration:30 -w Captures/PCAP/Flow.pcap
```
The `ip and inbound` filter keeps only the IPv4 packets entering the switch from each host, so every packet is captured once, at its sender's port. Without it, a packet between two hosts is captured twice (at the sender's and the receiver's port), and CICFlowMeter builds inconsistent flows: the model flagged only 14 of 3001 flows of an hping3 attack, and fragments of iperf transfers from the server as anomalies. The filter also drops ARP, which CICFlowMeter misreads as IPv4 flows such as `8.6.0.1 -> 8.0.6.4`. Keep `-f` before the `-i` options, or it only applies to the last interface.
5. ML engine:
```
cd Supervisor && python StartSupervisor.py
```

Alternatively, `Topology/Script PCAP to CSV/TsharkCIC.py` captures with pyshark and calls CICFlowMeter itself, replacing steps 3 and 4.

## How it works
> ⚠️ **WARNING**: **This is a bad pipeline, it should be optimized with a message queuing system like Kafka**
1. The pcap files will be saved with the format "Flow_{index}_{year}{month}{date}{hour}{minute}{second}.pcap"
2. The inotify tool in CICTrigger.sh will detect those PCAP files and automatically call the CICFlowMeter tool to convert those files into CSV Files with predefined features
3. The shared folder is used to send those CSV files directly to a repository in the Controller's server
4. StartSupervisor.py picks up every new CSV file in Captures/CSV, oldest first, they will be converted one last time to Dataframe and go through a trained ML model, sending out the prediction's result
5. Each anomalous flow adds 30 to its source's status in MongoDB, and the status decays by 10 per minute (applied each time a flow from that source is processed). The status is capped at 200, so a source drops below the threshold 10 minutes after its last anomaly. At 100 the source is blocked on its switch for 30 minutes, once per block period. While a host is blocked, flows from or to it are not scored: they cannot complete, and one-way flows look like anomalies to the model (constants at the top of StartSupervisor.py). If a source IP address is determined to be anomalous, the application will response with some actions in ManipAPI.Reaction. In this python file, 2 actions can be performed to indirectly modify flow entry of OpenFlow Switch by REST API (depending on the application running with the Controller):
 - Interact with rest_firewall
 - Interact with ofctl_rest
