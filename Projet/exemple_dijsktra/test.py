# ============================================
#         Dev pour Dijskra
# ============================================

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):

        pkt = packet.Packet(ev.msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        arp_pkt = pkt.get_protocol(arp.arp)
        ip4_pkt = pkt.get_protocol(ipv4.ipv4)
        if arp_pkt:
            pak = arp_pkt
        elif ip4_pkt:
            pak = ip4_pkt
        else:
            pak = eth

        self.logger.info('  _packet_in_handler: src_mac -> %s' % eth.src)
        self.logger.info('  _packet_in_handler: dst_mac -> %s' % eth.dst)
        self.logger.info('  _packet_in_handler: %s' % pak)
        self.logger.info('  ------')

        if eth.ethertype == ether_types.ETH_TYPE_LLDP or eth.ethertype == ether_types.ETH_TYPE_IPV6:
            # ignore lldp packet
            return

        dst = eth.src
        src = eth.dst
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        self.logger.info(">>>>>>> packet in %s %s %s %s", dpid, src, dst, in_port)
        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port
        print(src)
        print(dst)

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD
        actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]


        switch_list = get_switch(self, None)
        switches = [switch.dp.id for switch in switch_list]
        links_list = get_link(self, None)
        link_port={(link.src.dpid,link.dst.dpid):link.src.port_no for link in links_list}
        # g = nx.DiGraph()
        self.g.add_nodes_from(switches)
        links = [(link.src.dpid,link.dst.dpid,{'port':link.src.port_no}) for link in links_list]
        print(links)
        self.g.add_edges_from(links)
        links = [(link.dst.dpid,link.src.dpid,{'port':link.dst.port_no})  for link in links_list]
        self.g.add_edges_from(links)
        #print(links)
        #print(self.g)

	topo = {'1': {'2': 1, '3': 1},'2': {'1': 1, '3': 1},'3': {'1': 1, '2': 1}}

        dst_dpid = dpid_hostLookup(self, dst)
        print("dpid",str(dpid))
        print("dst",dst)
        # if(dst=='ff:ff:ff:ff:ff:ff'):
        #     return()
        path3=[]
        src=str(src)
        dst=str(dst)
        print("dst dpid",str(dst_dpid))
        if ((src == '42:97:0c:3b:eb:45' and dst == 'ae:6e:17:4e:a4:4b') or (src == '42:97:0c:3b:eb:45' and dst == '52:be:16:56:b4:47') or (
            src == 'ae:6e:17:4e:a4:4b' and dst == '42:97:0c:3b:eb:45') or(src == 'ae:6e:17:4e:a4:4b' and dst == '52:be:16:56:b4:47') or (
            src == '52:be:16:56:b4:47' and dst == '42:97:0c:3b:eb:45') or (src == '52:be:16:56:b4:47' and dst == 'ae:6e:17:4e:a4:4b')):
         dijkstra(topo, str(dpid), str(dst_dpid))
         global path2
         path3= list(map(int, path2))
         print(path3)
         path3.reverse()

        else:
            dijkstra_longestpath(topo, str(dpid), str(dst_dpid))
            path3 = list(map(int, path2))
            print(path3)
            path3.reverse()


        if not self.g.has_node(eth.src):
            print("add %s in self.net" % eth.src)
            self.g.add_node(eth.src)
            self.g.add_edge(eth.src, datapath.id)
            self.g.add_edge(datapath.id, eth.src, {'port': in_port})
            print(self.g.node)

        if not self.g.has_node(eth.dst):
            print("add %s in self.net" % eth.dst)
            self.g.add_node(eth.dst)
            self.g.add_edge(eth.dst, datapath.id)
            self.g.add_edge(datapath.id, eth.dst, {'port': in_port})
            print(self.g.node)

       # path3=[13,3,1]
        print("before loop")
        if(path3!=[]):
         if self.g.has_node(eth.dst):
            next_match = parser.OFPMatch(eth_dst=eth.dst)
            back_match = parser.OFPMatch(eth_dst=eth.src)
            print(path3)
            for on_path_switch in range(1, len(path3) - 1):
                print("hi in loop")
                now_switch = path3[on_path_switch]
                next_switch = path3[on_path_switch + 1]
                back_switch = path3[on_path_switch - 1]
                next_port = link_port[(now_switch,next_switch)]
                back_port = link_port[(now_switch,back_switch)]
                print("next_port",next_port)
                print("back_port",back_port)
                new_dp=get_datapath(self, next_switch)
                action = parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                                          [parser.OFPActionOutput(next_port)])
                inst = [action]
                self.add_flow(datapath=new_dp, match=next_match, inst=inst, table=0)

                action = parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                                          [parser.OFPActionOutput(back_port)])
                inst = [action]
                actions = [parser.OFPActionOutput(next_port)]
                new_dp = get_datapath(self, back_switch)
                self.add_flow(datapath=new_dp, match=back_match, inst=inst,actions=action, table=0)
                print ("now switch:%s",now_switch)
                out = datapath.ofproto_parser.OFPPacketOut(
                    datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port,
                    actions=actions)
                datapath.send_msg(out)
                print("final")

            else:
                return
        else:
            if out_port != ofproto.OFPP_FLOOD:
                self.add_flow(datapath, msg.in_port, dst, actions)

            out = datapath.ofproto_parser.OFPPacketOut(
                datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port,
                actions=actions)
            datapath.send_msg(out)
