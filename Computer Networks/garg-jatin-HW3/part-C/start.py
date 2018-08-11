#!/usr/bin/python

"""
Example network of Quagga routers
(QuaggaTopo + QuaggaService)
"""

import sys
import atexit

# patch isShellBuiltin
import mininet.util
import mininext.util
mininet.util.isShellBuiltin = mininext.util.isShellBuiltin
sys.modules['mininet.util'] = mininet.util

from mininet.util import dumpNodeConnections
from mininet.node import OVSController
from mininet.log import setLogLevel, info

from mininext.cli import CLI
from mininext.net import MiniNExT

from topo import QuaggaTopo

net = None


def startNetwork():
    "instantiates a topo, then starts the network and prints debug information"

    info('** Creating Quagga network topology\n')
    topo = QuaggaTopo()

    info('** Starting the network\n')
    global net
    net = MiniNExT(topo, controller=OVSController)
    net.start()

    info('** Dumping host connections\n')
    dumpNodeConnections(net.hosts)

    info('** Testing network connectivity\n')
    net.ping(net.hosts)

    info('** Dumping host processes\n')
    
    for i in range(2,6): 
        if i == 2:
            net.hosts[i].cmdPrint("ip addr add 192.0.0.201/30 dev R1-eth2")
            net.hosts[i].cmdPrint("ip addr add 192.0.0.197/30 dev R1-eth1")
        elif i == 3:
            net.hosts[i].cmdPrint("ip addr add 192.0.0.209/30 dev R2-eth1")
        elif i == 4:
            net.hosts[i].cmdPrint("ip addr add 192.0.0.205/30 dev R3-eth1")
        elif i == 5:
            net.hosts[i].cmdPrint("ip addr add 192.0.0.206/30 dev R4-eth1")
            net.hosts[i].cmdPrint("ip addr add 192.0.0.214/30 dev R4-eth2")


    for host in net.hosts: 
        host.cmdPrint("ps aux")
	host.cmdPrint("echo 1 > /proc/sys/net/ipv4/ip_forward")
    

    for i in range(len(net.hosts)):
        if i == 0:    
            net.hosts[i].cmdPrint("route add default gw 192.0.0.194")
        elif i == 1:
            net.hosts[i].cmdPrint("route add default gw 192.0.0.214")
        elif i == 2:
            net.hosts[i].cmdPrint("ip route add 192.0.0.204/30 via 192.0.0.202")
            net.hosts[i].cmdPrint("ip route add 192.0.0.208/30 via 192.0.0.198")
            net.hosts[i].cmdPrint("ip route add 192.0.0.212/30 via 192.0.0.198")
        elif i == 3:
            net.hosts[i].cmdPrint("ip route add 192.0.0.192/30 via 192.0.0.197")
            net.hosts[i].cmdPrint("ip route add 192.0.0.200/30 via 192.0.0.197")
            net.hosts[i].cmdPrint("ip route add 192.0.0.204/30 via 192.0.0.210")
            net.hosts[i].cmdPrint("ip route add 192.0.0.212/30 via 192.0.0.210")
        elif i == 4:
            net.hosts[i].cmdPrint("ip route add 192.0.0.192/30 via 192.0.0.201")
            net.hosts[i].cmdPrint("ip route add 192.0.0.196/30 via 192.0.0.201")
            net.hosts[i].cmdPrint("ip route add 192.0.0.208/30 via 192.0.0.201")
            net.hosts[i].cmdPrint("ip route add 192.0.0.212/30 via 192.0.0.206")
        elif i == 5:
            net.hosts[i].cmdPrint("ip route add 192.0.0.192/30 via 192.0.0.205")
            net.hosts[i].cmdPrint("ip route add 192.0.0.196/30 via 192.0.0.209")
            net.hosts[i].cmdPrint("ip route add 192.0.0.200/30 via 192.0.0.205")


    info('** Running CLI\n')
    CLI(net)


def stopNetwork():
    "stops a network (only called on a forced cleanup)"

    if net is not None:
        info('** Tearing down Quagga network\n')
        net.stop()

if __name__ == '__main__':
    # Force cleanup on exit by registering a cleanup function
    atexit.register(stopNetwork)

    # Tell mininet to print useful information
    setLogLevel('info')
    startNetwork()
