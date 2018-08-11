from RIPLite import *

def main():
    name = "H1"
    sport = 50001
    hostIPaddrs = "192.0.0.193"
    neighborsInfo = {
        "R1" : "192.0.0.194:50001"
    }
    myRIPLite = RIPLite(name, hostIPaddrs, neighborsInfo, sport)

if __name__ == "__main__":
    main()
