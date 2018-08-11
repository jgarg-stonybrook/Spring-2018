from RIPLite import *

def main():
    name = "R4"
    sport = 50001
    hostIPaddrs = "192.0.0.210"
    neighborsInfo = {
        "R2" : "192.0.0.209:50001",
        "R3" : "192.0.0.205:50001",
        "H2" : "192.0.0.213:50001"
    }
    myRIPLite = RIPLite(name, hostIPaddrs, neighborsInfo, sport)

if __name__ == "__main__":
    main()
