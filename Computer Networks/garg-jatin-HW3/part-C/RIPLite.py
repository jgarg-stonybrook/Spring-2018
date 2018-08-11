import time
import pickle
from socket import *
from threading import Thread
import collections
import logging

nodesList = ["H1", "R1", "R2", "R3", "R4", "H2"]

class RIPLite():
    def __init__(self, name, hostIPaddrs, neighborsInfo, sport):
        self.name = name

        logging.basicConfig(filename='./RipLogs/' + self.name + ".logs", format='%(asctime)s : %(message)s')
        self.logger = logging.getLogger('Rip-Logger')
        self.logger.setLevel(logging.INFO)
        self.logger.info("Started") 
        self.hostIPaddr = hostIPaddrs
        self.initial = 1
        self.neighborsInfo = neighborsInfo
        self.neighborNames = self.getNeighborNames()
        self.lastDistChangeTime = time.time()
        self.neighMatrix = self.getNeighMatrix()
        self.neighborsInfoDist = dict()
        self.end = 0
        self.neighborsInfoDist, isChanged = self.getCompleteNeighborInfo(neighborsInfo)
        self.distVector = self.getInitialDistVector(name)
        self.lastFileReadTime = time.time()
        myServerTh = ServerTh(sport, self)
        myServerTh.start()

        if self.initial == 1:
            self.clockTime = time.time()
            self.sendDistVecToNeighbor(self.distVector)
            self.initial = 0

        while True:
            if time.time() - self.lastFileReadTime >= 5:
                self.lastFileReadTime = time.time()
                self.neighborsInfoDist, isChanged = self.getCompleteNeighborInfo(self.neighborsInfo)
                if isChanged == 1:
                    self.logger.info("Weights changed !!!!")
                    self.end = 0
                    self.distVector = self.getInitialDistVector(self.name)
                    self.sendDistVecToNeighbor(self.distVector)

            time.sleep(5)

    def getNeighborNames(self):
        neighList = []
        for name in self.neighborsInfo:
            neighList.append(name)
        return neighList

    def getInitialDistVector(self, name):
        distDict = collections.OrderedDict()
        for node in nodesList:
            distDict[node] = [float("inf"), "Unknown"]
        distDict[name] = [0, name]
        return distDict

    def getNeighMatrix(self):
        neighMatrix = dict()
        for key in self.neighborNames + [self.name]:
            neighMatrix[key] = dict([(node, float("inf")) for node in nodesList])
        neighMatrix[self.name][self.name] = 0
        return neighMatrix

    def getCompleteNeighborInfo(self, neighborsInfo):
        neighborDist = dict()
        flag = 0
        for key in neighborsInfo.keys():
            if (self.neighborsInfoDist.__contains__(key)):
                prevWeight = self.neighborsInfoDist[key][1]
                if prevWeight != self.getWeightFromFile(self.name, key):
                    flag = 1
                self.clockTime = time.time()
            neighborDist[key] = (neighborsInfo[key], self.getWeightFromFile(self.name, key))
        return neighborDist, flag

    def updateDistVector(self, neighbor, neighborDistVector):
        flag = 0
        tempDistVector = self.getInitialDistVector(self.name)
        self.updateNeighMatrix(neighbor, neighborDistVector)

        for key in tempDistVector.keys():
            if key == self.name:
                continue

            for neigh in self.neighMatrix.keys():
                if neigh != self.name:

                    if tempDistVector[key][0] > self.neighMatrix[neigh][key] + self.neighborsInfoDist[neigh][1]:
                        tempDistVector[key][0] = self.neighMatrix[neigh][key] + self.neighborsInfoDist[neigh][1]
                        tempDistVector[key][1] = neigh

        if cmp(tempDistVector, self.distVector) != 0:
            flag = 1
            self.copyVectors(self.distVector, tempDistVector)

        if flag == 1:
            self.updateNeighMatrix(self.name, tempDistVector)
            self.logger.info("Routing Table for " + self.name)
            self.logger.info("Destination        " + "Distance        " + "Next Hop")
            for key in self.distVector.keys():
                self.logger.info("%s                 %.2f                  %s" %
                                 (key, self.distVector[key][0], self.distVector[key][1]))
            self.logger.info("Time Elapsed(msecs) from beginning: %.4f sec" % ((time.time() - self.clockTime)))
            self.logger.info("")
            self.logger.info("")
            self.lastDistChangeTime = time.time()
            self.sendDistVecToNeighbor(self.distVector)

    def copyVectors(self, dist1, dist2):
        for key in dist1.keys():
            dist1[key][0] = dist2[key][0]
            dist1[key][1] = dist2[key][1]

    def updateNeighMatrix(self, neighbor, neighborDistVector):
        for key in neighborDistVector.keys():
            self.neighMatrix[neighbor][key] =  neighborDistVector[key][0]


    def sendDistVecToNeighbor(self, distVector):
        for key in self.neighborsInfoDist.keys():
            ip = self.neighborsInfoDist[key][0].split(":")[0]
            sPort = int(self.neighborsInfoDist[key][0].split(":")[1])
            try:
                sSocket = socket(AF_INET, SOCK_STREAM)
                sSocket.connect((ip, sPort))
                sSocket.sendall(pickle.dumps((self.name,distVector)))
            except:
                pass

    def getWeightFromFile(self, fromm, to):
        f = open("RoutingInfo.txt", "r")
        for st in f:
            if st.__contains__(fromm + "-" + to) or st.__contains__(to + "-" + fromm):
                if float(st.split("=")[1]) < 0:
                    return float("inf")
                return float(st.split("=")[1])

class ServerTh(Thread):
    def __init__(self, sport, ripLite):
        super(ServerTh, self).__init__()
        self.sPort = sport
        self.ripLite = ripLite
        self.sSocket = socket(AF_INET, SOCK_STREAM)
        self.sSocket.bind(("", self.sPort))
        self.sSocket.listen(10)

    def run(self):
        while(True):
            connSocket, connAddr = self.sSocket.accept()
            neighbor, neighborDistVector = pickle.loads(connSocket.recv(4096))
            time.sleep(0.05)
            self.ripLite.updateDistVector(neighbor, neighborDistVector)
