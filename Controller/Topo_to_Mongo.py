import os
import sys
from datetime import datetime

# Reaction.py lives in Supervisor/ManipAPI and is shared with the Supervisor
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'Supervisor', 'ManipAPI'))
from Reaction import RESTDBconfig

from ryu.app import simple_switch_13
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub
from ryu.topology.api import get_host

SYNC_SECONDS = 15


class ControlTopo13(simple_switch_13.SimpleSwitch13):
    """L2 switch that keeps MongoDB's Topology collection in sync with the hosts Ryu discovers.

    Each document is {'Datapath ID': dpid, 'Hosts': [{'IP': ip, 'Status': score}], 'Version': timestamp}.
    The Supervisor reads it to map a source IP to its switch and keeps the Status score.
    """

    def __init__(self, *args, **kwargs):
        super(ControlTopo13, self).__init__(*args, **kwargs)
        self.datapaths = {}
        try:
            self.DB = RESTDBconfig()
            self.logger.info('Connected to Database.')
        except Exception:
            self.DB = None
            self.logger.error('Cannot connect to the Database', exc_info=True)
        self.monitor_thread = hub.spawn(self._monitor)

    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.logger.debug('register datapath: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.debug('unregister datapath: %016x', datapath.id)
                del self.datapaths[datapath.id]

    def _monitor(self):
        while True:
            hub.sleep(SYNC_SECONDS)
            if self.DB is None:
                continue
            for dpid in list(self.datapaths):
                self._sync_hosts(dpid)

    def _get_hosts(self, dpid):
        """IPv4 addresses of the hosts Ryu has seen attached to this switch."""
        return [ip for host in get_host(self, dpid=dpid) for ip in host.ipv4]

    def _sync_hosts(self, dpid):
        try:
            hosts = self._get_hosts(dpid)
            self.DB.DBconfig_sync_hosts(dpid, hosts, datetime.now().strftime("%Y%m%d%H%M%S"))
            self.logger.debug('Switch %d hosts in database: %s', dpid, hosts)
        except Exception:
            self.logger.error('Cannot update the hosts of switch %d in the database', dpid, exc_info=True)
