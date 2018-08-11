"""
Example topology of Quagga routers
"""

import inspect
import os
from mininext.topo import Topo
from mininext.services.quagga import QuaggaService

from collections import namedtuple

QuaggaHost = namedtuple("QuaggaHost", "name ip loIP")
net = None


class QuaggaTopo(Topo):

    "Creates a topology of Quagga routers"

    def __init__(self):
        """Initialize a Quagga topology with 5 routers, configure their IP
           addresses, loop back interfaces, and paths to their private
           configuration directories."""
        Topo.__init__(self)

        # Directory where this file / script is located"
        selfPath = os.path.dirname(os.path.abspath(
            inspect.getfile(inspect.currentframe())))  # script directory

        # Initialize a service helper for Quagga with default options
        quaggaSvc = QuaggaService(autoStop=False)

        # Path configurations for mounts
        quaggaBaseConfigPath = selfPath + '/configs/'

        # List of Quagga host configs
        quaggaHosts = []
	quagHostList = list()
        quaggaHosts.append(QuaggaHost(name='H1', ip='192.0.0.193/30', loIP="None"))
        quaggaHosts.append(QuaggaHost(name='R1', ip='192.0.0.194/30', loIP="None"))
        quaggaHosts.append(QuaggaHost(name='R2', ip='192.0.0.198/30', loIP="None"))
        quaggaHosts.append(QuaggaHost(name='R3', ip='192.0.0.202/30', loIP="None"))
        quaggaHosts.append(QuaggaHost(name='R4', ip='192.0.0.210/30', loIP="None"))
        quaggaHosts.append(QuaggaHost(name='H2', ip='192.0.0.213/30', loIP="None"))

        # Add switch for IXP fabric
        #ixpfabric = self.addSwitch('fabric-sw1')

        # Setup each Quagga router, add a link between it and the IXP fabric
        for host in quaggaHosts:

            # Create an instance of a host, called a quaggaContainer
            quagHostList.append(self.addHost(name=host.name,
                                           ip=host.ip,
                                           hostname=host.name,
                                           privateLogDir=True,
                                           privateRunDir=True,
                                           inMountNamespace=True,
                                           inPIDNamespace=True,
                                           inUTSNamespace=True))

            # Add a loopback interface with an IP in router's announced range
            #self.addNodeLoopbackIntf(node=host.name, ip=host.loIP)

            # Configure and setup the Quagga service for this node
            quaggaSvcConfig = \
                {'quaggaConfigPath': quaggaBaseConfigPath + host.name}
            self.addNodeService(node=host.name, service=quaggaSvc,
                                nodeConfig=quaggaSvcConfig)

        # Attach the quaggaContainer to the IXP Fabric Switch
	self.addLink(quagHostList[0], quagHostList[1])
	self.addLink(quagHostList[1], quagHostList[2])
	self.addLink(quagHostList[1], quagHostList[3])
	self.addLink(quagHostList[2], quagHostList[4])
	self.addLink(quagHostList[3], quagHostList[4])
	self.addLink(quagHostList[4], quagHostList[5])
