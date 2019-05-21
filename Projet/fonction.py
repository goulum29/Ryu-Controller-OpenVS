    def send_udp_hello_all_gw(self):#Envoi de paquet UDP à toutes les gateway, à faire boucler
        #gateways = self.routing_tbl.get_gateways()
        #for gateway in gateways:
            #address = self.address_data.get_data(ip=gateway)
            #self.send_hello_request()

    def send_hello_request(self, src_ip, dst_ip, in_port=None):#Fonction envoyant un paquet hello
        #for send_port in self.port_data.values():
            #if in_port is None or in_port != send_port.port_no:
                #src_mac = send_port.mac
                #dst_mac = mac_lib.BROADCAST_STR
                #ip_dst = dst_ip
                #inport = send_port.port_no
                #output = send_port.port_no