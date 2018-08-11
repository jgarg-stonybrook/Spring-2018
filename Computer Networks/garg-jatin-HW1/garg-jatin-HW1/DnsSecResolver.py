import dns.resolver
import dns
import dns.query
import sys

ROOT = "."
serverDict = dict()
parentDSRecord = str()
maxi = str()
kskList = list()
def initialServerDict():
    global serverDict
    global kskList

    kskList =    ["257 3 8 AwEAAagAIKlVZrpC6Ia7gEzahOR+9W29 euxhJhVVLOyQbSEW0O8gcCjFFVQUTf6v 58fLjwBd0YI0"
                  "EzrAcQqBGCzh/RStIoO8 g0NfnfL2MTJRkxoXbfDaUeVPQuYEhg37 NZWAJQ9VnMVDxP/VHL496M/QZxkjf5/E fucp2gaDX6RS6CXpoY68L"
                  "svPVjR0ZSwz z1apAzvN9dlzEheX7ICJBBtuA6G3LQpz W5hOA2hzCTMjJPJ8LbqF6dsV6DoBQzgu l0sGIcGOYl7OyQdXfZ57relSQageu+ip"
                  "AdTTJ25AsRTAoub8ONGcLmqrAmRLKBP1 dfwhYB4N7knNnulqQxA+Uk1ihz0=",
                  "257 3 8 AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexT BAvkMgJzkKTOiW1vkIbzxeF3+/4RgWOq 7HrxRixHlFlExOLA"
                  "Jr5emLvN7SWXgnLh 4+B5xQlNVz8Og8kvArMtNROxVQuCaSnI DdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLr jyBxWezF0jLHwVN8efS3rCj/EWg"
                  "vIWgb 9tarpVUDK/b58Da+sqqls3eNbuv7pr+e oZG+SrDK6nWeL3c6H5Apxz7LjVc1uTId sIXxuOLYA4/ilBmSVIzuDWfdRUfhHdY6 +cn8H"
                  "FRm+2hM8AnXGXws9555KrUB5qih ylGa8subX2Nn6UwNR1AkUTV74bU="]

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

def rootVerification(answer):
    global kskList

    for key in answer[0]:
        keyid = str(key).split(" ")[4]
        if keyid == "257":
            if key[0] not in kskList:
                return False
    return True


def getSplittedDomains(domainName):
    counter = len(domainName.strip(".").split("."))
    return domainName.strip("."), counter


def getSingleNameResolved(domain,counter):
    global serverDict

    dnsKeysVerificationResult, dnskeysRRset = getDNSKEYVerfication(domain,counter)
    if dnsKeysVerificationResult == "Fail":
        return "Fail"
    else:
        if dnsKeysVerificationResult == "NotEnabled":
            return "NotEnabled"

    dsRecordVerifictionResult,isAnswer = getDSRecordVerificationResult(domain,counter,dnskeysRRset)
    if isAnswer == "Fail":
        return "Fail"
    elif isAnswer == "NotEnabled":
        return "NotEnabled"

    return dsRecordVerifictionResult

def doParentToChildVerification(dnskeysRRset,domain):
    global parentDSRecord

    name = dns.name.from_text(domain)

    parentDSRecordList = list()
    for dsRecord in parentDSRecord:
        parentDSRecordList.append(str(dsRecord).split(" ")[3])

    kskListLocal = list()
    for key in dnskeysRRset:
        keyid = str(key).split(" ")[0]
        if keyid == "257":
            kskListLocal.append(key)

    for key in kskListLocal:
        ds = dns.dnssec.make_ds(name, key, "SHA256")
        hashed = str(ds).split(" ")[3]
        if hashed in parentDSRecordList:
            return True
        ds = dns.dnssec.make_ds(name, key, "SHA1")
        hashed = str(ds).split(" ")[3]
        if hashed in parentDSRecordList:
            return True

    return False

def getDNSKEYVerfication(domain,counter):
    global serverDict
    if counter == 0:
        serverName = "."
    else:
        serverName = ".".join(domain.split(".")[-counter:])

    response = None

    request = dns.message.make_query(serverName, 48 , want_dnssec=True)
    for serverKey in serverDict.keys():
        try:
            response = dns.query.tcp(request, serverDict.get(serverKey), timeout = 0.5)
        except:
            pass
        else:
            if len(response.answer) == 0:
                continue
            break

    if response is None or len(response.answer) < 2:
        return "NotEnabled", None

    dnskeysRRset, dnsKeyRRsig = None, None
    for record in response.answer:
        if type(record[0]) == dns.rdtypes.ANY.DNSKEY.DNSKEY:
            dnskeysRRset = record
        elif type(record[0]) == dns.rdtypes.ANY.RRSIG.RRSIG:
            dnsKeyRRsig = record

    if serverName == ".":
        result = rootVerification(response.answer)
    else:
        result = doParentToChildVerification(dnskeysRRset,serverName)

    if result == False:
        return "Fail", None

    name = dns.name.from_text(serverName)
    try:
        dns.dnssec.validate(dnskeysRRset, dnsKeyRRsig, {name: dnskeysRRset})
    except :
        return "Fail", None
    else:
        return "NotAnswer", dnskeysRRset

def getDSRecordVerificationResult(domain,counter,dnskeysRRset):
    global serverDict
    global maxi
    global parentDSRecord

    if counter == 0:
        name = "."
    else:
        name = ".".join(domain.split(".")[-counter:])

    response = None
    request = dns.message.make_query(domain, dns.rdatatype.A, want_dnssec=True)
    for serverKey in serverDict.keys():
        try:
            response = dns.query.tcp(request, serverDict.get(serverKey),timeout = 0.5)
        except:
            pass
        else:
            break

    if len(response.answer) > 0:
        return response, "NoAnswer"

    if len(response.authority) < 2:
        return False, "NotEnabled"

    dsRecordRRsig, dsRecordRRset = None, None
    for record in response.authority:
        if type(record[0]) == dns.rdtypes.ANY.RRSIG.RRSIG:
            dsRecordRRsig = record
        elif type(record[0]) == dns.rdtypes.ANY.DS.DS:
            dsRecordRRset = record

    if dsRecordRRsig is None or dsRecordRRset is None:
        return False, "NotEnabled"

    parentDSRecord = dsRecordRRset

    name = dns.name.from_text(name)

    try:
        dns.dnssec.validate(dsRecordRRset, dsRecordRRsig, {name: dnskeysRRset})
    except dns.dnssec.ValidationFailure:
        return False, "Fail"
    else:
        return response,"NoAnswer"


def updateServerDict(additional):
    global serverDict
    serverDict = dict()

    for i in range(len(additional)):
        if str(additional[i]).split(" ")[3] == "A":
            serverDict[str(additional[i]).split(" ")[0]] = str(additional[i][0])

def processResponseAnswer(answer,queryType):
    answer = str(answer)
    lis = answer.split(" ")

    for i in range(len(lis)):
        if lis[i].__eq__(queryType):
            return True , None
    return False ,lis[4]

def updateServerDictFromNSRecord(authority,queryType):
    global serverDict
    global maxi

    for record in authority:
        initialServerDict()
        ansback = myResolver(str(record[0]),queryType)

        if type(ansback) == str:
            return ansback
        ansback = (ansback[0].answer[0])
        serverDict = dict()
        if ansback is not None:
            serverDict[str(ansback).split(" ")[0]] = str(ansback).split(" ")[4]
            break
    return list()

def myResolver(domainName,queryType):
    global maxi
    global serverDict
    global parentDSRecord
    initialServerDict()
    domainName, counter = getSplittedDomains(domainName)

    result = list()
    i = 0
    while i <= counter:
        domain = domainName
        response = getSingleNameResolved(domain, i)
        if response == "Fail":
            neg = "DNSSec verification failed"
            return neg
        elif response == "NotEnabled":
            notEnable = "DNSSEC not supported"
            return notEnable
        else:
            if len(response.additional) > 0 and len(response.answer) == 0:
                updateServerDict(response.additional)
            elif len(response.answer) > 0 or i == counter:
                result.append(response)
                if len(response.answer) == 0 or queryType != "A":
                    return result

                flag, newdomain = processResponseAnswer(response.answer[0], queryType)
                if flag == True:
                    return result
                else:
                    ans = myResolver(str(newdomain), queryType)
                    if len(ans) > 0:
                        result.append(ans[0])
                    return result
            elif len(response.authority) > 0:
                if (str(response.authority[0]).split(" ")[3]) == "NS":
                    temp = parentDSRecord
                    res = updateServerDictFromNSRecord(response.authority, "A")
                    if type(res) == str:
                        return res
                    parentDSRecord = temp
        i += 1


def main():

    if len(sys.argv) < 2:
        print("Less Arguments")
    domainName = sys.argv[1]

    try:
        response = myResolver(domainName, "A")
        if response == "DNSSec verification failed":
            print(response)
        elif response == "DNSSEC not supported":
            print(response)
        else:
            print(response[0].answer[0][0])
    except:
        print("DNS RESOLUTION FAILED")


if __name__ == "__main__":
    main()
