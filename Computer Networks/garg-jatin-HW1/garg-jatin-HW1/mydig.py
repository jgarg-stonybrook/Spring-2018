import dns.resolver
import dns
import dns.query
import time
import sys
from datetime import datetime

serverDict = dict()
def initialServerDict():
    global serverDict
    serverDict = dict()
    serverDict = {
    'a.root-servers.net':'198.41.0.4',
    'b.root-servers.net':'199.9.14.201',
    'c.root-servers.net':'192.33.4.12',
    'd.root-servers.net':'199.7.91.13',
    'e.root-servers.net':'192.203.230.10',
    'f.root-servers.net':'192.5.5.241',
    'g.root-servers.net':'192.112.36.4',
    'h.root-servers.net':'198.97.190.53',
    'i.root-servers.net':'192.36.148.17',
    'j.root-servers.net':'192.58.128.30',
    'k.root-servers.net':'193.0.14.129',
    'l.root-servers.net':'199.7.83.42',
    'm.root-servers.net':'202.12.27.33'
    }


def getSingleNameResolved(domain,queryType):
    global serverDict
    mResolver = dns.resolver.Resolver()
    mResolver.timeout = 0.5
    mResolver.lifetime = 0.5
    for key in serverDict.keys():
        mResolver.nameservers = [serverDict[key]]
        try:
            ans = mResolver.query(domain, queryType, raise_on_no_answer=False)
        except dns.exception.Timeout:
            pass
        else:
            if ans is not None and ans.response.rcode != dns.rcode.NOERROR:
                return ans

def getSplittedDomains(domainName,queryType):
    counter = len(domainName.strip(".").split("."))
    return domainName.strip("."), counter

def updateServerDict(answer):
    global serverDict
    serverDict = dict()
    for i in range(len(answer.response.additional)):
        if str(answer.response.additional[i]).split(" ")[3] == "A":
            serverDict[str(answer.response.additional[i]).split(" ")[0]] = str(answer.response.additional[i][0])

def updateServerDictFromNSRecord(authority,queryType):
    global serverDict
    for record in authority:
        initialServerDict()
        ansback = myResolver(str(record[0]),queryType)
        if ansback is not None:
            serverDict[str(record[0])] = ansback[0]
            break

def getMessageSize(message):
    size = 0
    for rec in message:
        if len(str(rec)) > 0:
            size += len(str(rec))
    return size

def processResponseAnswer(answer,queryType):
    if queryType != "A":
        return True, None
    answer = str(answer)
    lis = answer.split(" ")
    for i in range(len(lis)):
        if lis[i].__eq__(queryType):
            return True , None
    return False ,lis[4]

def extractResult(result):
    resolution = str()
    size = 0
    flag = 0
    resolution += "ANSWER SECTION:\n"
    for record in result:
        if record is not None:
            if len(record.answer) > 0:
                flag = 1
                size += getMessageSize(record.answer)
                resolution += (str(record.answer[0]))
                resolution += "\n"

    if flag:
        return resolution,size

    resolution += "Authority Section:\n"
    for record in result:
        if record is not None:
            if len(record.authority) > 0:
                size += getMessageSize(record.authority)
                resolution += (str(record.authority[0]))
                resolution += "\n"
    return resolution,size


def myResolver(domainName,queryType):
    global serverDict
    initialServerDict()
    domainName,counter = getSplittedDomains(domainName,queryType)

    result = list()
    i = 0

    while i <= counter:
        domain = domainName
        answer = getSingleNameResolved(domain,queryType)
        if len(answer.response.additional) > 0 and len(answer.response.answer) == 0:
            updateServerDict(answer)
        elif len(answer.response.answer) > 0 or i == counter:
            result.append(answer.response)
            if len(answer.response.answer) == 0 or queryType != "A":
                return result

            flag,newdomain = processResponseAnswer(answer.response.answer[0],queryType)
            if flag == True:
                return result
            else:
                ans = myResolver(str(newdomain),queryType)
                if len(ans) > 0:
                    result.append(ans[0])
                return result
        elif len(answer.response.authority) > 0:
            if (str(answer.response.authority[0]).split(" ")[3]) == "NS":
                counter += 1
                updateServerDictFromNSRecord(answer.response.authority,"A")
        i += 1


def main():
    with open('mydig_output.txt', 'a') as f:
        if len(sys.argv) < 3:
            print("Less Arguments","mydig_output",file=f)
            return
        domainName = sys.argv[1]
        queryType = sys.argv[2]

        try:
            print("QUESTION SECTION:\n%s IN %s" % (domainName, queryType), "\n", file=f)
            start = time.time()
            answer = myResolver(domainName,queryType)
            end = time.time()
            totaltime = str((end-start)*1000)
            resolution,msgSize = extractResult(answer)

            print(resolution,file=f)
            print("Query time:  ",totaltime.split(".")[0]," msec",file = f)
            print("WHEN: ,",datetime.now().strftime('%a %b %d %H:%M:%S %Y'),file = f)
            print("MSG SIZE rcvd: ",msgSize,file = f)
        except:
            print("DNS RESOLUTION FAILED")

if __name__ == "__main__":
    main()
