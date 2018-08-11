import dpkt
from bitstring import BitArray
import struct
import string

# In[320]:

# Packet Structure of Ethernet Packet:
#     First 14 bytes for Ethernet Protocol Fields:(0-13)
#         Destination Mac Address : 6 bytes
#         Source Mac Address : 6 bytes
#         Type of IP Packet : 2 bytes
#         Note : Preamble and FCS are stripped off
#     Next is for (eth.data) which is an IP packet(Length = 20 bytes):
#         Version, IHL, QoS : (2 bytes) [14:15]
#         Length of IPv4 packet(excluding ETh header)(2 bytes) [16:17]
#         Identification, Frag Offset (4 bytes)[18:21]
#         TTL (1 bytes) [22]
#         Protocol used (1 byte) [23] (TCP = 6)
#         Checksum (2 bytes) [24:25]
#         Source IP (4 bytes) [26:29]
#         Destination IP (4 bytes) [30:33]
#     Next is TCP header and Data (Length = Specified by data offset)
#         Source Port (2 bytes) [34:35]
#         Destination Port (2 bytes) [36:37]
#         Seq Number (4 bytes) [38:41]
#         Ack Number (4 bytes) [42:45]
#         Data Off and future Reservation (1 byte) [46]
#         Flags (---ACk PSH RST SYN FIN) (1 byte) [47]
#         Window Size (2 bytes) [48:49]
#         Checksum (2 bytes) [50:51]
#         URG Pointer (2 bytes) [52:53]
#         Optionals:
#             Option-kind [54] (1 byte) [54]
#             Option-Length (1 byte) [55]
#             MSS (if Option-Kind is 2) (2 bytes) [56:57]
#             Option (1 byte) (8 for timestamp)
#             Length (1 byte) (Length For timestamps)
#             TSECR (4 bytes)
#             TSVAl (4 bytes)
#             No Option = 1
#     Data after Data Offset 


# In[321]:

class TCPConnection:
    def __init__(self):
        self.avgRTT = 0
        self.avgTs = 0
        self.fastReTranspacket = 0
        self.retransPacket = 0
        self.startSeqNumberSrc = 0
        self.startSeqNumberDest = 0
        self.totalPackSent = 0
        self.successPackSent = 0
        self.throughPut = 0
        self.srcWinScale = 0
        self.dstWinScale = 0
        self.srcPacketList = list()
        self.destPacketList = list()
        self.mss = 0


# In[322]:

class Packet:
    def __init__(self, ts, packetArr):
#         14 is size of Ethernet Header in starting
#         20 is size of IP header after Ethernet header. After this TCP header starts
        self.timeSmp = ts
        self.lenPacket = struct.unpack('!H', packetArr[16:18])[0] + 14 
        self.sport = struct.unpack('!H', packetArr[34:36])[0]
        self.dport = struct.unpack('!H', packetArr[36:38])[0]
        self.seqNum = struct.unpack('!L', packetArr[38:42])[0]
        self.ackNum = struct.unpack('!L', packetArr[42:46])[0]
        self.dataOffset = (struct.unpack('!B', packetArr[46:47])[0] >> 4) * 4 + (34)
        self.cwr = BitArray(bytes = packetArr[47:48]).bin[0]
        self.ack = BitArray(bytes = packetArr[47:48]).bin[3]
        self.psh = BitArray(bytes = packetArr[47:48]).bin[4]
        self.syn = BitArray(bytes = packetArr[47:48]).bin[6]
        self.fin = BitArray(bytes = packetArr[47:48]).bin[7]
        self.winSize = struct.unpack("!H", packetArr[48:50])[0]
        self.dataLen = self.lenPacket - self.dataOffset
        self.maxSegSize = 0
        self.tsVal = 0
        self.tsEchRep = 0
        self.winScale = 0
        self.getRequest = ""
        self.postResponse = ""
        self.actualData = ""
        
#         Option byte is 2 if MSS is present
#         Option byte is 8 for TSVAL and TSECHREP
        index = 54
        while index < self.dataOffset:
            if (struct.unpack('!B', packetArr[index: index + 1])[0]) == 2:
                self.maxSegSize = struct.unpack('!H', packetArr[index + 2 : index + 4])[0]
                index += 4
                continue
            elif (struct.unpack('!B', packetArr[index: index + 1])[0]) == 8:
                self.tsVal = struct.unpack('!L', packetArr[index + 2 : index + 6])[0]
                self.tsEchRep = struct.unpack('!L', packetArr[index + 6 : index + 10])[0]
                index += 10
                continue
            elif (struct.unpack('!B', packetArr[index: index + 1])[0]) == 3:
                self.winScale = struct.unpack('!B', packetArr[index + 2 : index + 3])[0]
                self.winScale = (2 ** self.winScale)
                index += 3
                continue
            elif (struct.unpack('!B', packetArr[index: index + 1])[0]) == 0:
                index += 1
                continue
            elif (struct.unpack('!B', packetArr[index: index + 1])[0]) == 1:
                index += 1
                continue
            else :
                index += 1
                index += (struct.unpack('!B', packetArr[index : index + 1])[0]) - 1
            
        index = self.dataOffset
        if index < self.lenPacket:
            try:
                temp = (struct.unpack('!s', packetArr[index:index+1])[0]).decode("UTF-8", errors="ignore") +                         (struct.unpack('!s',packetArr[index+1 : index +2])[0]).decode("UTF-8", errors="ignore") +                             (struct.unpack('!s', packetArr[index+2 : index +3])[0]).decode("UTF-8", errors="ignore")
                
                if temp == "GET":
                    self.getRequest = temp
                else:
                    temp += (struct.unpack('!s', packetArr[index+3 : index+4])[0]).decode("UTF-8", errors="ignore")
                    
                    if temp == "HTTP":
                        self.postResponse = temp
                        
                if self.getRequest == 'GET' or self.postResponse == 'HTTP':
                    self.actualData = struct.unpack("!%ds" % (self.lenPacket-index), packetArr[index:])[0].                                            decode('utf-8',errors='ignore')

            except struct.error:
                pass


# In[323]:
tcpConnectionMap = dict()
sourceIP = "172.24.19.53"
destinationIP = "34.193.77.105"

def parseConnectionPackets(filename):
    global tcpConnectionMap
    allSourcePacketList = list()
    allDestinationPacketList = list()

    pcapFile = open(filename, 'rb')

    pcapReader = dpkt.pcap.Reader(pcapFile)
    count = 0
    for ts, packetArr in pcapReader:
        count += 1
        if sourceIP == ".".join(map(str,(struct.unpack('!BBBB', packetArr[26:30])))):
            allSourcePacketList.append(Packet(ts, packetArr))
        if destinationIP == ".".join(map(str,(struct.unpack('!BBBB', packetArr[26:30])))):
            allDestinationPacketList.append(Packet(ts, packetArr))

    portWisePacketMap = dict()

    for packet in allSourcePacketList:
        tup = (packet.sport, packet.dport)
        if portWisePacketMap.__contains__(tup) == False:
            temp = list()
            temp.append(packet)
            portWisePacketMap[tup] = temp
        else:
            temp = portWisePacketMap.get(tup)
            temp.append(packet)
            portWisePacketMap[tup] = temp


    for packet in allDestinationPacketList:
        tup = (packet.sport, packet.dport)
        if portWisePacketMap.__contains__(tup) == False:
            temp = list()
            temp.append(packet)
            portWisePacketMap[tup] = temp
        else:
            temp = portWisePacketMap.get(tup)
            temp.append(packet)
            portWisePacketMap[tup] = temp


    for key in portWisePacketMap.keys():
        if tcpConnectionMap.__contains__(key) == False:
            pacList = portWisePacketMap[key]
            if pacList[0].ack == '1' and pacList[0].syn == '1':
                conn = TCPConnection()
                srcPackList = portWisePacketMap[(key[1], key[0])]
                conn.mss = pacList[0].maxSegSize
                conn.srcWinScale = srcPackList[0].winScale
                conn.dstWinScale = pacList[0].winScale
                conn.startSeqNumberSrc = srcPackList[0].seqNum
                conn.startSeqNumberDest = pacList[0].seqNum
                conn.totalPackSent = len(portWisePacketMap[(key[1], key[0])])
                conn.srcPacketList = portWisePacketMap[(key[1], key[0])]
                conn.destPacketList = portWisePacketMap[key]
                tcpConnectionMap[(key[1], key[0])] = conn


# In[334]:

# Part C Question 1

def generateGET_HTTPPairs(tcpConnectionMap):
    for key, conn in tcpConnectionMap.items():
        seqStartSrc = conn.startSeqNumberSrc
        seqStartDest = conn.startSeqNumberDest
        srcPacketList = conn.srcPacketList
        dstPacketList = conn.destPacketList
        minTime = 0
        flag = 0
        with open('analysis_pcap_http_output_Part_A.txt', 'a') as f:
            for i in range(len(srcPacketList)):
                if srcPacketList[i].getRequest == "GET":
                    print(srcPacketList[i].actualData, file = f)
                    break

            for i in range(len(dstPacketList)):
                if flag == 1 and dstPacketList[i].timeSmp >= minTime and \
                        (dstPacketList[i].lenPacket > dstPacketList[i].dataOffset):
                    print((dstPacketList[i].sport, dstPacketList[i].dport, dstPacketList[i].seqNum - seqStartDest,\
                            dstPacketList[i].ackNum - seqStartSrc), file = f)
                if dstPacketList[i].postResponse == "HTTP":
                    temp = str(dstPacketList[i].actualData)
                    filtered_string = "\n".join(temp.split("\n")[:9])
                    print(filtered_string, file = f)
                    print(file = f)
                    print("<Source Port, Destination Port, Seq Number, Ack Nmmber>", file = f)
                    print((dstPacketList[i].sport, dstPacketList[i].dport, dstPacketList[i].seqNum - seqStartDest,\
                            dstPacketList[i].ackNum - seqStartSrc), file = f)
                    minTime = srcPacketList[i].timeSmp
                    flag = 1

            print(file=f)
            print(file=f)


    # In[333]:
# Part C Question 2
def countFlows(tcpConnectionMap):
    with open('analysis_pcap_http_out_B_C.txt', 'a') as f:
        print("Total TCP Flows Initiated from Seneder " + sourceIP + " are: " + str(len(tcpConnectionMap)), file = f)

# In[301]:

# Part C Question 3
def generateStats(tcpConnectionMap):
    with open('analysis_pcap_http_out_B_C.txt', 'a') as f:

        totalPacket = 0
        totalData = 0
        totalTime = 0
        count = 0
        endTime = float("-inf")
        startTime = 0
        for key, conn in tcpConnectionMap.items():
            srcPacketList = conn.srcPacketList
            dstPacketList = conn.destPacketList
            totalPacket += len(srcPacketList)

            if count == 0:
            # if startTime < srcPacketList[0].timeSmp:
                startTime = srcPacketList[0].timeSmp
                count += 1

            if endTime < dstPacketList[-1].timeSmp:
                endTime = dstPacketList[-1].timeSmp

            for i in range(len(srcPacketList)):
                totalData += srcPacketList[i].lenPacket

        totalTime += (endTime - startTime)

        print("Total Data(Bytes) from client side is:", totalData, file = f)
        print("Total Number of Packets from client side is :", totalPacket, file = f)
        print("Total Time taken to load page is :", totalTime, file = f)
        print(file = f)
        print(file = f)


def main():

    global tcpConnectionMap
    tcpConnectionMap = dict()
    filename = "http_1080.pcap"
    parseConnectionPackets(filename)
    generateGET_HTTPPairs(tcpConnectionMap)
    countFlows(tcpConnectionMap)
    generateStats(tcpConnectionMap)

    tcpConnectionMap = dict()
    filename = "http_1081.pcap"
    parseConnectionPackets(filename)
    countFlows(tcpConnectionMap)
    generateStats(tcpConnectionMap)

    tcpConnectionMap = dict()
    filename = "http_1082.pcap"
    parseConnectionPackets(filename)
    countFlows(tcpConnectionMap)
    generateStats(tcpConnectionMap)


if __name__  == '__main__':
    main()