"""Custom topology example

Two directly connected switches plus a host for each switch:

   host --- switch --- switch --- host

Adding the 'topos' dict with a key/value pair to generate our newly defined
topology enables one to pass in '--topo=mytopo' from the command line.
"""

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import CPULimitedHost
from mininet.link import TCLink
from mininet.util import dumpNodeConnections
from mininet.log import setLogLevel

class MyTopo( Topo ):
    "Simple topology example."

    def __init__( self ):
        "Create custom topo."

        # Initialize topology
        Topo.__init__( self )

        # Add hosts and switches
        host1 = self.addHost( 'h1', ip='192.168.10.1/24',defaultRoute='via 192.168.10.254')
        host2 = self.addHost( 'h2', ip='192.168.20.1/24',defaultRoute='via 192.168.20.254')
        host3 = self.addHost( 'h3', ip='192.168.30.1/24',defaultRoute='via 192.168.30.254')
        host4 = self.addHost( 'h4', ip='192.168.40.1/24',defaultRoute='via 192.168.40.254')
        host5 = self.addHost( 'h5', ip='192.168.50.1/24',defaultRoute='via 192.168.30.254')
        host6 = self.addHost( 'h6', ip='192.168.60.1/24',defaultRoute='via 192.168.30.254')
        switch1 = self.addSwitch( 's1' )
        switch2 = self.addSwitch( 's2' )
        switch3 = self.addSwitch( 's3' )
        switch4 = self.addSwitch( 's4' )
        switch5 = self.addSwitch( 's5' )
        switch6 = self.addSwitch( 's6' )
        # Add links
        self.addLink( switch1, host1, cls=TCLink,bw=10)
        self.addLink( switch2, host2,cls=TCLink, bw=10)
        self.addLink( switch3, host3,cls=TCLink, bw=10)
        self.addLink( switch1, switch2 , cls=TCLink,bw=10)
        self.addLink( switch2, switch3, cls=TCLink,bw=10)
        self.addLink( switch1, switch3 ,cls=TCLink, bw=10)
        self.addLink( switch3, switch4 ,cls=TCLink, bw=10)
        self.addLink( switch4, switch5 ,cls=TCLink, bw=10)
        self.addLink( switch5, switch6 ,cls=TCLink, bw=10)
topos = { 'mytopo': ( lambda: MyTopo() ) }
