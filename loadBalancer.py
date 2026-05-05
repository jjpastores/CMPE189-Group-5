from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet, arp, ipv4, tcp, udp, ether_types


class DynamicLoadBalancer(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    VIP = "10.0.0.10"
    VMAC = "00:00:00:00:00:10"

    SERVERS = {
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

    def __init__(self, *args, **kwargs):
        super(DynamicLoadBalancer, self).__init__(*args, **kwargs)
        self.flow_to_server = {}
        self.logger.info("Dynamic Least-Connections Load Balancer Started")

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        parser = datapath.ofproto_parser
        ofp = datapath.ofproto

        match = parser.OFPMatch()
        actions = [
            parser.OFPActionOutput(
                ofp.OFPP_CONTROLLER,
                ofp.OFPCML_NO_BUFFER
            )
        ]

        self.add_flow(datapath, 0, match, actions)
        self.logger.info("Switch connected")

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        parser = datapath.ofproto_parser
        ofp = datapath.ofproto
        in_port = msg.match["in_port"]

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        if eth is None:
            return

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        arp_pkt = pkt.get_protocol(arp.arp)
        ip_pkt = pkt.get_protocol(ipv4.ipv4)

        if arp_pkt:
            self.handle_arp(datapath, parser, ofp, in_port, eth, arp_pkt)
            return

        if ip_pkt:
            self.handle_ipv4(datapath, parser, ofp, in_port, eth, ip_pkt, pkt, msg.data)
            return

    def handle_arp(self, datapath, parser, ofp, in_port, eth, arp_pkt):
        if arp_pkt.opcode == arp.ARP_REQUEST and arp_pkt.dst_ip == self.VIP:
            self.send_arp_reply(
                datapath=datapath,
                parser=parser,
                ofp=ofp,
                in_port=in_port,
                dst_mac=eth.src,
                dst_ip=arp_pkt.src_ip,
                src_mac=self.VMAC,
                src_ip=self.VIP
            )

    def handle_ipv4(self, datapath, parser, ofp, in_port, eth, ip_pkt, pkt, data):
        if ip_pkt.dst != self.VIP:
            return

        proto = ip_pkt.proto
        src_port = None
        dst_port = None

        tcp_pkt = pkt.get_protocol(tcp.tcp)
        udp_pkt = pkt.get_protocol(udp.udp)

        if tcp_pkt:
            src_port = tcp_pkt.src_port
            dst_port = tcp_pkt.dst_port
        elif udp_pkt:
            src_port = udp_pkt.src_port
            dst_port = udp_pkt.dst_port
        else:
            return

        client_ip = ip_pkt.src
        client_mac = eth.src

        flow_key = (
            client_ip,
            self.VIP,
            proto,
            src_port,
            dst_port
        )

        if flow_key in self.flow_to_server:
            server_ip = self.flow_to_server[flow_key]
        else:
            server_ip = self.choose_least_connection_server()
            self.flow_to_server[flow_key] = server_ip
            self.SERVERS[server_ip]["connections"] += 1

        server = self.SERVERS[server_ip]

        self.logger.info(
            "Flow %s assigned to server %s | connections=%s",
            flow_key,
            server_ip,
            {
                ip: self.SERVERS[ip]["connections"]
                for ip in self.SERVERS
            }
        )

        self.install_flows(
            datapath=datapath,
            parser=parser,
            ofp=ofp,
            client_ip=client_ip,
            client_mac=client_mac,
            client_port=in_port,
            server_ip=server_ip,
            server=server,
            proto=proto,
            src_port=src_port,
            dst_port=dst_port
        )

        actions = [
            parser.OFPActionSetField(ipv4_dst=server_ip),
            parser.OFPActionSetField(eth_dst=server["mac"]),
            parser.OFPActionOutput(server["port"])
        ]

        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=ofp.OFP_NO_BUFFER,
            in_port=in_port,
            actions=actions,
            data=data
        )

        datapath.send_msg(out)

    def choose_least_connection_server(self):
        return min(
            self.SERVERS,
            key=lambda ip: self.SERVERS[ip]["connections"]
        )

    def install_flows(
        self,
        datapath,
        parser,
        ofp,
        client_ip,
        client_mac,
        client_port,
        server_ip,
        server,
        proto,
        src_port,
        dst_port
    ):
        if proto == 6:
            match_to_server = parser.OFPMatch(
                eth_type=0x0800,
                ip_proto=6,
                ipv4_src=client_ip,
                ipv4_dst=self.VIP,
                tcp_src=src_port,
                tcp_dst=dst_port
            )

            match_to_client = parser.OFPMatch(
                eth_type=0x0800,
                ip_proto=6,
                ipv4_src=server_ip,
                ipv4_dst=client_ip,
                tcp_src=dst_port,
                tcp_dst=src_port
            )

        elif proto == 17:
            match_to_server = parser.OFPMatch(
                eth_type=0x0800,
                ip_proto=17,
                ipv4_src=client_ip,
                ipv4_dst=self.VIP,
                udp_src=src_port,
                udp_dst=dst_port
            )

            match_to_client = parser.OFPMatch(
                eth_type=0x0800,
                ip_proto=17,
                ipv4_src=server_ip,
                ipv4_dst=client_ip,
                udp_src=dst_port,
                udp_dst=src_port
            )

        else:
            return

        actions_to_server = [
            parser.OFPActionSetField(ipv4_dst=server_ip),
            parser.OFPActionSetField(eth_dst=server["mac"]),
            parser.OFPActionOutput(server["port"])
        ]

        actions_to_client = [
            parser.OFPActionSetField(ipv4_src=self.VIP),
            parser.OFPActionSetField(eth_src=self.VMAC),
            parser.OFPActionSetField(eth_dst=client_mac),
            parser.OFPActionOutput(client_port)
        ]

        self.add_flow(
            datapath,
            priority=20,
            match=match_to_server,
            actions=actions_to_server,
            idle_timeout=30,
            hard_timeout=0,
            send_flow_rem=True
        )

        self.add_flow(
            datapath,
            priority=20,
            match=match_to_client,
            actions=actions_to_client,
            idle_timeout=30,
            hard_timeout=0,
            send_flow_rem=False
        )

    @set_ev_cls(ofp_event.EventOFPFlowRemoved, MAIN_DISPATCHER)
    def flow_removed_handler(self, ev):
        msg = ev.msg
        match = msg.match

        if "ipv4_src" not in match or "ipv4_dst" not in match:
            return

        client_ip = match["ipv4_src"]
        vip = match["ipv4_dst"]

        if vip != self.VIP:
            return

        proto = match.get("ip_proto")

        if proto == 6:
            src_port = match.get("tcp_src")
            dst_port = match.get("tcp_dst")
        elif proto == 17:
            src_port = match.get("udp_src")
            dst_port = match.get("udp_dst")
        else:
            return

        flow_key = (
            client_ip,
            self.VIP,
            proto,
            src_port,
            dst_port
        )

        server_ip = self.flow_to_server.pop(flow_key, None)

        if server_ip and server_ip in self.SERVERS:
            if self.SERVERS[server_ip]["connections"] > 0:
                self.SERVERS[server_ip]["connections"] -= 1

            self.logger.info(
                "Flow expired: %s removed from %s | connections=%s",
                flow_key,
                server_ip,
                {
                    ip: self.SERVERS[ip]["connections"]
                    for ip in self.SERVERS
                }
            )

    def send_arp_reply(
        self,
        datapath,
        parser,
        ofp,
        in_port,
        dst_mac,
        dst_ip,
        src_mac,
        src_ip
    ):
        eth_reply = ethernet.ethernet(
            dst=dst_mac,
            src=src_mac,
            ethertype=ether_types.ETH_TYPE_ARP
        )

        arp_reply = arp.arp(
            hwtype=1,
            proto=0x0800,
            hlen=6,
            plen=4,
            opcode=arp.ARP_REPLY,
            src_mac=src_mac,
            src_ip=src_ip,
            dst_mac=dst_mac,
            dst_ip=dst_ip
        )

        pkt = packet.Packet()
        pkt.add_protocol(eth_reply)
        pkt.add_protocol(arp_reply)
        pkt.serialize()

        actions = [
            parser.OFPActionOutput(ofp.OFPP_IN_PORT)
        ]

        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=ofp.OFP_NO_BUFFER,
            in_port=in_port,
            actions=actions,
            data=pkt.data
        )

        datapath.send_msg(out)

    def add_flow(
        self,
        datapath,
        priority,
        match,
        actions,
        idle_timeout=0,
        hard_timeout=0,
        send_flow_rem=False
    ):
        parser = datapath.ofproto_parser
        ofp = datapath.ofproto

        inst = [
            parser.OFPInstructionActions(
                ofp.OFPIT_APPLY_ACTIONS,
                actions
            )
        ]

        flags = 0
        if send_flow_rem:
            flags = ofp.OFPFF_SEND_FLOW_REM

        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=priority,
            match=match,
            instructions=inst,
            idle_timeout=idle_timeout,
            hard_timeout=hard_timeout,
            flags=flags
        )

        datapath.send_msg(mod)