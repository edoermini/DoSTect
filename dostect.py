import argparse
import os
import socket
import netifaces
from core.traffic import OfflineCatcher, LiveCatcher
from core.graph import Graph
import sys
import ipaddress

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
    parser = argparse.ArgumentParser(description="DoSTect allow to detect SYN flooding attack with Parametric/Non Parametric CUSUM change point detection")
    
    # Create an exclusive group: in this group only one parameter can be used at time
    source_group = parser.add_mutually_exclusive_group(required=True)
    source_group.add_argument('-i','--interface', action='store', dest="interface",
                        help="Network interface from which to perform live capture",
                        metavar="INTERFACE",
                        type=lambda x: is_valid_interface(parser, x))

    source_group.add_argument('-f','--file', action='store', dest="file",
                        help="Packet capture file", metavar="FILE.pcap/.pcapng",
                        type=lambda x: is_valid_capture(parser, x))

    parser.add_argument('-s', '--slice', dest='interval', action='store',default=5.0,
                        help="Specify duration of time interval observation (ex: 5.0, 10.00)")
   
    parser.add_argument("-p", "--parametric",  action='store', dest="param",type=bool, nargs='?',
                        const=True, default=False,
                        help="Activate parametric mode")

    parser.add_argument("-g", '--graph',  action='store', dest="graph",type=bool, nargs='?',
                        const=True, default=False,
                        help="Activate influxDB data sender")

    parser.add_argument('-t', '--threshold', action='store', dest="threshold",
                        help="Threshold detection value for Parametric CUSUM", type=float)
    
    parser.add_argument('-a', '--address', action='store', dest="address",
                        help=" IPv4 address of attacked machine for PCAP capture", type=str)
    

    # TODO: graph thread termination interrupt
    # Arguments parser
    args = parser.parse_args()

    # Check param && threshold dependency
    #if (args.param and args.threshold is None) or (not args.param and args.threshold is not None):
    #    parser.error("-param requires -threshold [FLOAT].")

    # Check file && localaddr dependency
    if (args.file and args.address is None) or (args.interface and args.address is not None):
        parser.error("--pcap requires --address [LOCAL ADDRESS].")
    
    elif args.file is not None:
         # Check localaddr format
        try: 
            ipaddress.IPv4Address(args.address)
        except:
            parser.error("%s is not an IPv4 address!" % str(args.address))

    # Initialize to default value if None
    if args.threshold is None:
        args.threshold = 0.65

    # Initialize to Graph module if -g mode
    plot = None
    if args.graph:
        plot = Graph()

    # Start live capture if file is None (-i [INTERFACE] mode)
    if args.file is None:
        analyzer = LiveCatcher(
            source=str(args.interface),
            plot=plot,
            parametric=args.param,
            time_interval=int(args.interval),
            threshold=float(args.threshold)
        )
    else:
        # Start analyzer from PCAP capture (-r [FILE] mode)
        analyzer = OfflineCatcher(
            source=str(args.file),
            ipv4_address=str(args.address),
            plot=plot,
            parametric=args.param,
            time_interval=int(args.interval),
            threshold=float(args.threshold),
        )
    
    try:
        # Start analyzer
        analyzer.start()
    except (KeyboardInterrupt, SystemExit):
        sys.exit()
   

if __name__ == "__main__":
    main()
