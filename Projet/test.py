# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib.packet import arp
from ryu.ofproto import ofproto_v1_4
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import ipv4
from ryu.lib.packet import icmp
from ryu.lib.packet.arp import arp
from ryu.lib.packet.packet import Packet
import array

HOST_IPADDR1 = "10.1.1.2"
HOST_IPADDR2 = "10.1.4.2"
ROUTER_IPADDR1 = "10.1.1.1"
ROUTER_IPADDR2 = "10.1.4.1"
ROUTER_MACADDR1 = "00:00:00:00:00:01"
ROUTER_MACADDR2 = "00:00:00:00:00:02"
ROUTER_PORT1 = 1
ROUTER_PORT2 = 2

class SimpleSwitch14(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_4.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch14, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.arpTable = {}#ip to mac

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]

        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst)
        datapath.send_msg(mod)

    def receive_arp(self,datapath,packet,etherFrame,inPort):
        arpPacket = packet.get_protocol(arp)
        if arpPacket.opcode == 1 :
            arp_dstIp = arpPacket.dst_ip
            self.logger.debug('received ARP Request %s => %s (port%d)'%(etherFrame.src,etherFrame.dst,inPort))
            self.reply_arp(datapath,etherFrame,arpPacket,arp_dstIp,inPort)
        elif arpPacket.opcode == 2 :
            pass

    def reply_arp(self, datapath, etherFrame, arpPacket, arp_dstIp, inPort):
        dstIp = arpPacket.src_ip
        srcIp = arpPacket.dst_ip
        dstMac = etherFrame.src
        self.logger.debug("ARP dstIp: %s"%arp_dstIp)
        if arp_dstIp == ROUTER_IPADDR1:
            srcMac = ROUTER_MACADDR1
            outPort = ROUTER_PORT1
        elif arp_dstIp == ROUTER_IPADDR2:
            srcMac = ROUTER_MACADDR2
            outPort = ROUTER_PORT2
        else:
            self.logger.debug("unknown arp request received !")
        self.send_arp(datapath, 2, srcMac, srcIp, dstMac, dstIp, outPort)
        self.logger.debug("send ARP reply %s => %s (port%d)" %(srcMac, dstMac, outPort))

    def send_arp(self, datapath, opcode, srcMac, srcIp, dstMac, dstIp, outPort):
        if opcode == 1:
            targetMac = "00:00:00:00:00:00"
            targetIp = dstIp
        elif opcode == 2:
            targetMac = dstMac
            targetIp = dstIp
        e = ethernet.ethernet(dstMac, srcMac, ether_types.ETH_TYPE_ARP)
        a = arp(1, 0x0800, 6, 4, opcode, srcMac, srcIp, targetMac, targetIp)
        p = Packet()
        p.add_protocol(e)
        p.add_protocol(a)
        p.serialize()
        actions = [datapath.ofproto_parser.OFPActionOutput(outPort, 0)]
        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=0xffffffff,
            in_port=datapath.ofproto.OFPP_CONTROLLER,
            actions=actions,
            data=p.data)
        datapath.send_msg(out)

    def _send_packet(self, datapath, port, pkt):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        pkt.serialize()
        self.logger.info("packet-out %s" % (pkt,))
        data = pkt.data
        actions = [parser.OFPActionOutput(port=port)]
        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=ofproto.OFPP_CONTROLLER,
                                  actions=actions,
                                  data=data)
        datapath.send_msg(out)

    def _handle_icmp(self, datapath, port, pkt_ethernet, pkt_ipv4, pkt_icmp):
        if pkt_icmp.type != icmp.ICMP_ECHO_REQUEST:
            return
        pkt = packet.Packet()
        pkt.add_protocol(ethernet.ethernet(ethertype=pkt_ethernet.ethertype,
                                           dst=pkt_ethernet.src,
                                           src=ROUTER_MACADDR1))
        pkt.add_protocol(ipv4.ipv4(dst=pkt_ipv4.src,
                                   src=ROUTER_IPADDR1,
                                   proto=pkt_ipv4.proto))
        pkt.add_protocol(icmp.icmp(type_=icmp.ICMP_ECHO_REPLY,
                                   code=icmp.ICMP_ECHO_REPLY_CODE,
                                   csum=0,
                                   data=pkt_icmp.data))
        self._send_packet(datapath, port, pkt)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        self.logger.info('%s'%eth.ethertype)
        dst = eth.dst
        src = eth.src
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        self.logger.info("packet in dpid: %s, srce: %s, dest: %s, in_port: %s", dpid, src, dst, in_port)
        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port
        if eth.ethertype == ether_types.ETH_TYPE_ARP:
            self.receive_arp(datapath,pkt,eth,in_port)
        #learn mac to ip 
        if eth.ethertype == ether_types.ETH_TYPE_IP:
            ipv4_pak = pkt.get_protocol(ipv4.ipv4)
            icmp_pak = pkt.get_protocol(icmp.icmp)
            self.logger.info('packet_in_handler: --> %s'%ipv4_pak)
            if dst == ROUTER_MACADDR1:
                out_port = 2
                actions.append( OFPActionSetField(eth_src=ROUTER_MACADDR2) )
                actions.append( OFPActionSetField(eth_dst='b2:64:b7:5f:5a:97') )

            elif dst == ROUTER_MACADDR2:
                out_port = 1
                actions.append( OFPActionSetField(eth_src=ROUTER_MACADDR1) )
                actions.append( OFPActionSetField(eth_dst='a2:86:fb:29:dc:57 ') )
            else:
                self.logger.info('Not working')
                return
            out = parser.OFPPacketOut(datapath = datapath,
                                      buffer_id = ofproto.OFP_NO_BUFFER,
                                      in_port = in_port,
                                      actions = actions,
                                      data = msg.data)
            self.logger.info('packet_out:--> %s'%out)
            datapath.send_msg(out)