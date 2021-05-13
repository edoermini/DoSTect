import argparse
import os
import socket
import netifaces
from core.traffic import TrafficAnalyzer

# Check if the input file has a valid extension
def is_valid_capture(parser, arg):
    if not os.path.exists(arg):
        parser.error("The file %s does not exist!" % arg)
    else:
        ext = os.path.splitext(arg)[-1].lower() # Get file extension

        if ext != ".pcap" and ext != ".pcapng": # Check supported extensions
             parser.error("The file %s is of an incorrect format" % arg)
        else:
            return arg  # Return an open file handle

# Check if the interface exists
def is_valid_interface(parser, arg):
    if arg in netifaces.interfaces():
        return arg
    else:
        parser.error("Interface %s not found" % arg)

   

def main():
    parser = argparse.ArgumentParser(description="DoSTect allow to detect SYN flooding attack with CUSUM/EWMA forecasting alghorithm")
    
    # Create an exclusive group: in this group only one parameter can be used at time
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-i','-interface', action='store', dest="interface", 
                        help="Network interface from which to perform live capture",
                        metavar="INTERFACE",
                        type=lambda x: is_valid_interface(parser, x))

    group.add_argument('-r','-pcap', action='store', dest="file",
                        help="Packet capture file", metavar="FILE.pcap/.pcapng",
                        type=lambda x: is_valid_capture(parser, x))

    # Parse from keyboard
    args = parser.parse_args()
    if args.file is None:
        source = str(args.interface)
        analyzer = TrafficAnalyzer(source, live_capture=True)
    else:
        source = str(args.file)
        analyzer = TrafficAnalyzer(source)

    analyzer.start()
    

if __name__ == "__main__":
    main()
