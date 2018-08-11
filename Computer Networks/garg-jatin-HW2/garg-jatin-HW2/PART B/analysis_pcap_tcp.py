import dpkt
from bitstring import BitArray
import struct
import collections

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


# In[434]:

allSourcePacketList = list()
allDestinationPacketList = list()


# In[435]:

sourceIP = "130.245.145.12"
destinationIP = "128.208.2.198"


# In[436]:

pcapFile = open("assignment2.pcap", 'rb')

pcapReader = dpkt.pcap.Reader(pcapFile)
count = 0
for ts, packetArr in pcapReader:
    if sourceIP == ".".join(map(str,(struct.unpack('!BBBB', packetArr[26:30])))):
        allSourcePacketList.append(Packet(ts, packetArr))
    if destinationIP == ".".join(map(str,(struct.unpack('!BBBB', packetArr[26:30])))):
        allDestinationPacketList.append(Packet(ts, packetArr))


# In[437]:

# print(len(allSourcePacketList))
# print(len(allDestinationPacketList))


# In[438]:

portWisePacketMap = dict()


# In[439]:

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


# In[440]:

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


# In[441]:

tcpConnectionMap = dict()


# In[442]:

for key in portWisePacketMap.keys():
    # print(key)
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


# In[443]:
with open('analysis_pcap_tcp_output.txt', 'a') as f:
    # Part A Question 1
    print("Part A Question 1", file = f)

    # In[444]:

    print("Total TCP Flows Initiated from Seneder " + sourceIP + " are: " + str(len(tcpConnectionMap)), file = f)
    print(file = f)

    # In[447]:
    print("Max Segment Size for TCP connections", file = f)
    for key, conn in tcpConnectionMap.items():
        print("MSS for ",conn.srcPacketList[0].sport," is : ", conn.mss, file = f)

    print(file = f)
    # Part A Question 2.a
    print("Part A Question 2.a (Client (Syn, Ack), Server(Syn, Ack)", file = f)

    # In[691]:

    for key, conn in tcpConnectionMap.items():
        seqStartSrc = conn.startSeqNumberSrc
        seqStartDest = conn.startSeqNumberDest
        srcPacketList = conn.srcPacketList
        dstPacketList = conn.destPacketList
        count = 0
        print("For TCP Connection:", str(srcPacketList[0].sport), file = f)
        for i in range(2,len(srcPacketList)):
            for j in range(1,len(dstPacketList)):
                if (srcPacketList[i].seqNum - seqStartSrc + srcPacketList[i].dataLen) == (dstPacketList[j].ackNum - seqStartSrc):
                        print("Syn =",srcPacketList[i].seqNum - seqStartSrc,"Ack =", srcPacketList[i].ackNum-seqStartDest,\
                                "Syn =", dstPacketList[j].seqNum - seqStartDest, "Ack =",dstPacketList[j].ackNum-seqStartSrc, file = f)
                        print("Receive Window Size: ", "Src =", srcPacketList[i].winSize * conn.srcWinScale, \
                                " Dst =", dstPacketList[j].winSize * conn.dstWinScale, file = f)

                        count += 1
                if count == 2:
                    break
            print(file = f)
            if count == 2:
                break


    # In[448]:

    # Part A Question 2.b
    print("Part A Question 2.b", file = f)
    # In[688]:

    for key, conn in tcpConnectionMap.items():
        seqStartSrc = conn.startSeqNumberSrc
        srcPacketList = conn.srcPacketList
        dstPacketList = conn.destPacketList
        totalData = 0
        startTime = srcPacketList[0].timeSmp
        endTime = dstPacketList[-1].timeSmp
        senderDict = dict()

        for i in range(len(srcPacketList)):
            if senderDict.__contains__(srcPacketList[i].seqNum-seqStartSrc) == False:
                senderDict[srcPacketList[i].seqNum-seqStartSrc] = 1
                totalData += srcPacketList[i].lenPacket

        print("Total Empirical Throughput(KB/Sec) for",\
                str(srcPacketList[0].sport),"TCP Connection is :",str(totalData/((endTime-startTime)*1024)), file = f)
    print(file = f)

    # In[462]:

    # Part A Question 2.c
    print("Part A Question 2.c", file = f)

    # In[687]:

    for key, conn in tcpConnectionMap.items():
        seqStartSrc = conn.startSeqNumberSrc
        srcPacketList = conn.srcPacketList
        lastAckNum = conn.destPacketList[-1].ackNum
    #   Packet with SYN 1 is sent twice
        totalSuccess = 1
        totalPacketSent = conn.totalPackSent
        senderDict = dict()
        for i in range(len(srcPacketList)):
            if senderDict.__contains__(srcPacketList[i].seqNum-seqStartSrc) == False:
                if (srcPacketList[i].seqNum-seqStartSrc) <= (lastAckNum-seqStartSrc):
                    senderDict[srcPacketList[i].seqNum-seqStartSrc] = 1
                    totalSuccess += 1
        print("Total Loss Rate(lost/total) for",str(srcPacketList[0].sport),"TCP Connection is :",\
                (totalPacketSent-totalSuccess)/totalPacketSent, file = f)
    print(file = f)

    # In[628]:

    # Part A Question 2.d
    print("Part A Question 2.d", file = f)
    # In[686]:

    for key, conn in tcpConnectionMap.items():
        seqStartSrc = conn.startSeqNumberSrc
        srcPacketList = conn.srcPacketList

        dstpacketList = conn.destPacketList
        srcTSDict = collections.OrderedDict()
        dstTSDict = collections.OrderedDict()
        iRTT = dstpacketList[0].timeSmp - srcPacketList[0].timeSmp

        pacCount = 1
        for i in range(2, len(srcPacketList)):
            tup = ((srcPacketList[i].seqNum - seqStartSrc + srcPacketList[i].dataLen), srcPacketList[i].tsVal)
            srcTSDict[tup] = srcPacketList[i].timeSmp

        for i in range(1, len(dstpacketList)):
            tup = ((dstpacketList[i].ackNum - seqStartSrc), dstpacketList[i].tsEchRep)
            dstTSDict[tup] = dstpacketList[i].timeSmp

        for key in dstTSDict.keys():
            if srcTSDict.__contains__(key):
                pacCount += 1
                iRTT += (dstTSDict[key] - srcTSDict[key])

        print("Average RTT(secs) for", str(srcPacketList[0].sport), "TCP Connection is :",\
                (iRTT)/pacCount, file = f)
    print(file = f)

    # In[642]:

    # Part B Question 1

    print("Part B Question 1", file = f)
    print("Format : Window Size BY Packets, Window Size BY Bytes", file = f)
    # In[685]:

    for key, conn in tcpConnectionMap.items():
        seqStartSrc = conn.startSeqNumberSrc
        srcPacketList = conn.srcPacketList[2:]
        print("Congestion windows for",str(srcPacketList[0].sport),"TCP Flow :", file = f)
        dstpacketList = conn.destPacketList[1:]
        lastAckReq = i = j = 0
        count = 0
        maxdstNum = 0
        while i < len(dstpacketList):
            if (dstpacketList[i].ackNum - seqStartSrc) <= lastAckReq:
                i += 1
                continue
            congesWin = 0
            winSize = 0
            endTS = dstpacketList[i].timeSmp
            while j < len(srcPacketList):
                if srcPacketList[j].timeSmp < endTS:
                    congesWin += 1
                    winSize += srcPacketList[j].lenPacket
                    lastAckReq = srcPacketList[j].seqNum - seqStartSrc + srcPacketList[j].dataLen
                    j += 1
                    continue
                else:
                    break
            i += 1
            maxdstNum += i
            print("Congestion Window :", congesWin, winSize, file = f)
            count += 1
            if count == 10 or maxdstNum >= len(dstpacketList):
                break
        print(file = f)

    # In[634]:

    # Part B Question 2
    print("Part B Question 2", file = f)

    # In[619]:

    for key, conn in tcpConnectionMap.items():
        seqStartSrc = conn.startSeqNumberSrc
        srcPacketList = conn.srcPacketList
        dstpacketList = conn.destPacketList
        srcSeqDict = dict()
        dstAckDict = dict()
        fastRetransmission = 0
        for i in range(len(srcPacketList)):
            tup = srcPacketList[i].seqNum - seqStartSrc
            if srcSeqDict.__contains__(tup) == False:
                srcSeqDict[tup] = [1, srcPacketList[i].timeSmp]
            else:
                prev = srcSeqDict[tup]
                prev[0] += 1
                prev[1] = srcPacketList[i].timeSmp
                srcSeqDict[tup] = prev

        for i in range(len(dstpacketList)):
            tup = dstpacketList[i].ackNum - seqStartSrc
            if dstAckDict.__contains__(tup) == False:
                dstAckDict[tup] = [1, dstpacketList[i].timeSmp]
            else:
                prev = dstAckDict[tup]
                if prev[0] < 4:
                    prev[0] += 1
                    prev[1] = dstpacketList[i].timeSmp
                    dstAckDict[tup] = prev

        for key in srcSeqDict.keys():
            if dstAckDict.__contains__(key) and dstAckDict[key][0] > 3 and srcSeqDict[key][1] >= dstAckDict[key][1]:
                fastRetransmission += 1
        print("Number of Fast Retransmission for Port "+str(srcPacketList[0].sport)+" :",\
                fastRetransmission, file = f)

        srcSeqDict = dict()
    # Packet with seq 1 and transmitted twice in successful case also. So starting from -1
        reTransmission = -1
        for i in range(len(srcPacketList)):
            tup = ((srcPacketList[i].seqNum - seqStartSrc))
            if srcSeqDict.__contains__(tup) == False:
                srcSeqDict[tup] = 1
            else:
                reTransmission += 1
        print("Number of Retransmission(Timeout) for Port "+str(srcPacketList[0].sport)+" :",\
                reTransmission - fastRetransmission, file = f)
        print(file = f)