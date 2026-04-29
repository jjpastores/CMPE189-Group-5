from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import arp
from ryu.lib.packet import ipv4
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet.packet import Packet
from ryu.lib import hub

class DynamicLoadBalancer(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(DynamicLoadBalancer, self).__init__(*args, **kwargs)
        self.host_table = {}
        self.server_table = {}
        self.client_to_server = {}
        self.datapaths = {}

        self.virtual_ip = "10.0.0.10"
        self.virtual_mac = "00:00:00:00:00:10"

        self.algorithm = "least_connections"
        self.rr_index = 0

        self.logger.info("DynamicLoadBalancer started")

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        self.logger.info("Switch connected: datapath_id=%s", datapath.id)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        self.logger.info("PacketIn received")
