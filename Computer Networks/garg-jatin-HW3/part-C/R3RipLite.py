from RIPLite import *

def main():
    name = "R3"
    sport = 50001
    hostIPaddrs = "192.0.0.202"
    neighborsInfo = {
        "R1" : "192.0.0.201:50001",
        "R4" : "192.0.0.206:50001"
    }
    myRIPLite = RIPLite(name, hostIPaddrs, neighborsInfo, sport)

if __name__ == "__main__":
    main()
