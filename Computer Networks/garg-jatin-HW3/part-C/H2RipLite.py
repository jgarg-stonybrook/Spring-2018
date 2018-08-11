from RIPLite import *

def main():
    name = "H2"
    sport = 50001
    hostIPaddrs = "192.0.0.213"
    neighborsInfo = {
        "R4" : "192.0.0.214:50001"
    }
    myRIPLite = RIPLite(name, hostIPaddrs, neighborsInfo, sport)

if __name__ == "__main__":
    main()
