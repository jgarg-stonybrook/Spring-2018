#!/usr/bin/python

"""
Example network of Quagga routers
(QuaggaTopo + QuaggaService)
"""

import sys
import atexit
import time

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
argument = ""

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

    h2IPAddress= "192.0.0.213"
    
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

    if argument == "1":
        startTime = time.time()
        check = 'random'
        print("Checking Time taken by H1 to ping H2...Wait")

        while ' 0% packet loss' not in check :
            check = net.hosts[0].cmdPrint('ping -c10 ' + h2IPAddress)
            if ' 0% packet loss' not in check:
                print("Not able to ping in this ping..Trying again")

        print(check)
        endTime = time.time()
        print('H1 to H2 pinging time= ', (endTime - startTime), 'sec')
    
    if argument == "2":
        startTime = time.time()
    
        check = 1
        print("Checking Convergence Time....Wait")
        while check != 0 :
            check = net.pingAll()
            if check != 0:
                print("Not converged in this ping...Trying again")

        endTime = time.time()
        print('Convergence time= ', (endTime - startTime), 'sec')

        print('Do R1-R2 Link down')
        startTime = time.time()
        net.configLinkStatus('R1', 'R2', 'down')
        print("Link Down...Checking convergence Time")
        check = 'random'
        while ' 0% packet loss' not in check :
            check = net.hosts[0].cmdPrint('ping -c10 ' + h2IPAddress)
            if ' 0% packet loss' not in check:
                print("Not able to ping in this ping..Trying again")

        print(check)
        endTime = time.time()
        print('H1 to H2 pinging time= ', (endTime - startTime), 'sec')

    
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
    if len(sys.argv) == 2:
        argument = sys.argv[1]
    startNetwork()
