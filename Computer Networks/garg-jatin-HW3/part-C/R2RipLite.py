from RIPLite import *

def main():
    name = "R2"
    sport = 50001
    hostIPaddrs = "192.0.0.198"
    neighborsInfo = {
        "R1" : "192.0.0.197:50001",
        "R4" : "192.0.0.210:50001"
    }
    myRIPLite = RIPLite(name, hostIPaddrs, neighborsInfo, sport)

if __name__ == "__main__":
    main()
