import argparse
import os
import socket
import netifaces
from core.traffic import TrafficAnalyzer
from core.graph import Graph
import sys

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
    source_group = parser.add_mutually_exclusive_group(required=True)
    source_group.add_argument('-i','-interface', action='store', dest="interface", 
                        help="Network interface from which to perform live capture",
                        metavar="INTERFACE",
                        type=lambda x: is_valid_interface(parser, x))

    source_group.add_argument('-r','-pcap', action='store', dest="file",
                        help="Packet capture file", metavar="FILE.pcap/.pcapng",
                        type=lambda x: is_valid_capture(parser, x))
    parser.add_argument('-s', '-slice', dest='interval', action='store',default=5.0,
                        help="Specify duration of time interval observation (ex: 5.0, 10.00)")
   
    parser.add_argument("-p",  action='store', dest="param",type=bool, nargs='?',
                        const=True, default=False,
                        help="Activate parametric mode")
    parser.add_argument("-g", '-graph',  action='store', dest="graph",type=bool, nargs='?',
                        const=True, default=False,
                        help="Activate parametric mode")

    parser.add_argument('-t','-threshold', action='store', dest="threshold", default=0.65, 
                        help="Threshold detection value for Parametric CUSUM", type=float)
    
   # TODO: create exclusive group with (-t && -p) 
   # graph thread termination

    # Parse from keyboard
    args = parser.parse_args()
    plot = None
    if args.graph:
        plot = Graph()

    if args.file is None:
        source = str(args.interface)
        print("Threshold: " + str(args.threshold) +  " - Interval: " + str(args.interval) + " - Graph: " + str(args.graph) + " - Plot istance: " + str(plot))
        analyzer = TrafficAnalyzer(source, plot=plot, live_capture=True, parametric=args.param, time_interval=int(args.interval), threshold=float(args.threshold))
    else:
        source = str(args.file)
        analyzer = TrafficAnalyzer(source, plot)
    
    try:
        # Start analyzer
        analyzer.start()
    except (KeyboardInterrupt, SystemExit):
        sys.exit()
   
    

if __name__ == "__main__":
    main()
