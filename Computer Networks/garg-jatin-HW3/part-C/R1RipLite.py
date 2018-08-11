from RIPLite import *

def main():
    name = "R1"
    sport = 50001
    hostIPaddrs = "192.0.0.194"
    neighborsInfo = {
        "H1" : "192.0.0.193:50001",
        "R2" : "192.0.0.198:50001",
        "R3" : "192.0.0.202:50001"
    }
    myRIPLite = RIPLite(name, hostIPaddrs, neighborsInfo, sport)
    
if __name__ == "__main__":
    main()

