import socket
import struct

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
from ryu.lib.mac import haddr_to_bin


def _ipv4_to_int(ip_str):
    """OpenFlow 1.3 matches/set-field use IPv4 as a 32-bit integer."""
    return struct.unpack("!I", socket.inet_aton(ip_str))[0]


def _int_to_ipv4(value):
    """Convert 32-bit int (or masked tuple from OFPMatch) to dotted string."""
    if isinstance(value, tuple):
        value = value[0]
    return socket.inet_ntoa(struct.pack("!I", int(value)))


class DynamicLoadBalancer(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(DynamicLoadBalancer, self).__init__(*args, **kwargs)

        self.host_table = {}
        self.client_to_server = {}
        self.datapaths = {}

        self.virtual_ip = "10.0.0.10"
        self.virtual_mac = "00:00:00:00:00:10"

        self.algorithm = "least_connections"
        self.rr_index = 0

        self.server_table = {
            "10.0.0.5": {
                "mac": "00:00:00:00:00:05",
                "port": 5,
                "connections": 0
            },
            "10.0.0.6": {
                "mac": "00:00:00:00:00:06",
                "port": 6,
                "connections": 0
            }
        }

        self.logger.info("DynamicLoadBalancer started")

    def add_flow(self, datapath, priority, match, actions,
                 idle_timeout=0, hard_timeout=0, buffer_id=None, flags=0):
        """Install or update one flow on the given datapath."""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(
            ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=priority,
            match=match,
            instructions=inst,
            idle_timeout=idle_timeout,
            hard_timeout=hard_timeout,
            buffer_id=buffer_id,
            flags=flags,
        )
        datapath.send_msg(mod)

    def choose_server(self, client_ip):
        """
        Pick a backend for this client.
        Sticky: returning clients reuse the same server until flows expire.
        New clients use round_robin or least_connections (self.algorithm).
        """
        if client_ip in self.client_to_server:
            return self.client_to_server[client_ip]

        keys = list(self.server_table.keys())
        if self.algorithm == "round_robin":
            server_ip = keys[self.rr_index % len(keys)]
            self.rr_index += 1
        else:
            server_ip = min(
                keys,
                key=lambda k: self.server_table[k]["connections"],
            )
            self.server_table[server_ip]["connections"] += 1

        self.client_to_server[client_ip] = server_ip
        self.logger.info(
            "choose_server: client %s -> %s (%s)",
            client_ip,
            server_ip,
            self.algorithm,
        )
        return server_ip

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        self.datapaths[datapath.id] = datapath

        match = parser.OFPMatch()
        actions = [
            parser.OFPActionOutput(
                ofproto.OFPP_CONTROLLER,
                ofproto.OFPCML_NO_BUFFER
            )
        ]

        self.add_flow(datapath, 0, match, actions)

        self.logger.info("Switch connected: datapath_id=%s", datapath.id)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        in_port = msg.match["in_port"]

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        if eth is None:
            return

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        self.host_table[eth.src] = in_port

        arp_pkt = pkt.get_protocol(arp.arp)
        ip_pkt = pkt.get_protocol(ipv4.ipv4)

        if arp_pkt:
            self.host_table[arp_pkt.src_ip] = {
                "mac": eth.src,
                "port": in_port,
            }
            self.handle_arp(datapath, parser, ofproto, in_port, eth, arp_pkt)
            return

        if ip_pkt:
            self.host_table[ip_pkt.src] = {
                "mac": eth.src,
                "port": in_port,
            }
            self.handle_ipv4(
                datapath, parser, ofproto, in_port, eth, ip_pkt, msg)
            return

    def send_arp_reply(
        self,
        datapath,
        parser,
        ofproto,
        in_port,
        dst_mac,
        dst_ip,
        src_mac,
        src_ip,
    ):
        """Send an ARP reply as PacketOut to the port the request arrived on."""
        eth_pkt = ethernet.ethernet(
            dst=dst_mac,
            src=src_mac,
            ethertype=ether_types.ETH_TYPE_ARP,
        )
        arp_pkt = arp.arp(
            hwtype=1,
            proto=ether_types.ETH_TYPE_IP,
            hlen=6,
            plen=4,
            opcode=arp.ARP_REPLY,
            src_mac=src_mac,
            src_ip=src_ip,
            dst_mac=dst_mac,
            dst_ip=dst_ip,
        )
        p = packet.Packet()
        p.add_protocol(eth_pkt)
        p.add_protocol(arp_pkt)
        p.serialize()

        actions = [parser.OFPActionOutput(port=in_port)]
        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=ofproto.OFP_NO_BUFFER,
            in_port=ofproto.OFPP_CONTROLLER,
            actions=actions,
            data=p.data,
        )
        datapath.send_msg(out)

    def install_load_balancing_flows(
        self,
        datapath,
        parser,
        ofproto,
        client_ip,
        client_port,
        server_ip,
        server,
        buffer_id=None,
    ):
        """
        Client->VIP packets are rewritten to the real server; return traffic
        is rewritten so the client still sees the VIP as the source.
        """
        vip_int = _ipv4_to_int(self.virtual_ip)
        client_int = _ipv4_to_int(client_ip)
        server_int = _ipv4_to_int(server_ip)
        server_mac_bin = haddr_to_bin(server["mac"])
        vmac_bin = haddr_to_bin(self.virtual_mac)

        match_fwd = parser.OFPMatch(
            in_port=client_port,
            eth_type=ether_types.ETH_TYPE_IP,
            ipv4_src=client_int,
            ipv4_dst=vip_int,
        )
        actions_fwd = [
            parser.OFPActionSetField(eth_dst=server_mac_bin),
            parser.OFPActionSetField(ipv4_dst=server_int),
            parser.OFPActionOutput(port=server["port"]),
        ]
        self.add_flow(
            datapath,
            priority=20,
            match=match_fwd,
            actions=actions_fwd,
            idle_timeout=60,
            flags=ofproto.OFPFF_SEND_FLOW_REM,
        )

        match_rev = parser.OFPMatch(
            in_port=server["port"],
            eth_type=ether_types.ETH_TYPE_IP,
            ipv4_src=server_int,
            ipv4_dst=client_int,
        )
        actions_rev = [
            parser.OFPActionSetField(eth_src=vmac_bin),
            parser.OFPActionSetField(ipv4_src=vip_int),
            parser.OFPActionOutput(port=client_port),
        ]
        self.add_flow(
            datapath,
            priority=20,
            match=match_rev,
            actions=actions_rev,
            idle_timeout=60,
            flags=ofproto.OFPFF_SEND_FLOW_REM,
        )

        if buffer_id is not None and buffer_id != ofproto.OFP_NO_BUFFER:
            out = parser.OFPPacketOut(
                datapath=datapath,
                buffer_id=buffer_id,
                in_port=ofproto.OFPP_CONTROLLER,
                actions=actions_fwd,
            )
            datapath.send_msg(out)

    def handle_arp(self, datapath, parser, ofproto, in_port, eth, arp_pkt):
        src_ip = arp_pkt.src_ip
        dst_ip = arp_pkt.dst_ip
        src_mac = eth.src

        self.logger.info("ARP packet: %s asks for %s", src_ip, dst_ip)

        if dst_ip == self.virtual_ip:
            server_ip = self.choose_server(src_ip)
            server = self.server_table[server_ip]

            self.send_arp_reply(
                datapath=datapath,
                parser=parser,
                ofproto=ofproto,
                in_port=in_port,
                dst_mac=src_mac,
                dst_ip=src_ip,
                src_mac=self.virtual_mac,
                src_ip=self.virtual_ip
            )

            self.install_load_balancing_flows(
                datapath=datapath,
                parser=parser,
                ofproto=ofproto,
                client_ip=src_ip,
                client_port=in_port,
                server_ip=server_ip,
                server=server
            )

        elif dst_ip in self.server_table:
            server = self.server_table[dst_ip]

            self.send_arp_reply(
                datapath=datapath,
                parser=parser,
                ofproto=ofproto,
                in_port=in_port,
                dst_mac=src_mac,
                dst_ip=src_ip,
                src_mac=server["mac"],
                src_ip=dst_ip
            )
            
    def handle_ipv4(self, datapath, parser, ofproto, in_port, eth, ip_pkt, msg):
        if ip_pkt.dst != self.virtual_ip:
            return

        client_ip = ip_pkt.src
        server_ip = self.choose_server(client_ip)
        server = self.server_table[server_ip]

        self.install_load_balancing_flows(
            datapath=datapath,
            parser=parser,
            ofproto=ofproto,
            client_ip=client_ip,
            client_port=in_port,
            server_ip=server_ip,
            server=server,
            buffer_id=msg.buffer_id,
        )

    @set_ev_cls(ofp_event.EventOFPFlowRemoved, MAIN_DISPATCHER)
    def flow_removed_handler(self, ev):
        """
        When client->VIP flows idle out, drop sticky state and decrement
        least_connections counter so load estimates stay in sync.
        """
        msg = ev.msg
        ofproto = msg.datapath.ofproto
        match = msg.match

        if msg.reason not in (
            ofproto.OFPRR_IDLE_TIMEOUT,
            ofproto.OFPRR_HARD_TIMEOUT,
        ):
            return

        if "ipv4_dst" not in match or "ipv4_src" not in match:
            return

        vip_int = _ipv4_to_int(self.virtual_ip)
        try:
            dst = match["ipv4_dst"]
            if isinstance(dst, tuple):
                dst = dst[0]
            if int(dst) != vip_int:
                return
            client_ip = _int_to_ipv4(match["ipv4_src"])
        except (TypeError, ValueError, struct.error):
            return

        server_ip = self.client_to_server.pop(client_ip, None)
        if server_ip is None or server_ip not in self.server_table:
            return

        c = self.server_table[server_ip]["connections"]
        if c > 0:
            self.server_table[server_ip]["connections"] = c - 1

        self.logger.info(
            "flow_removed: client %s released from %s (reason=%s)",
            client_ip,
            server_ip,
            msg.reason,
        )


