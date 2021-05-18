import argparse
import os
import socket
import netifaces
from core.traffic import TrafficAnalyzer
from core.graph import Graph

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
    parser.add_argument('--s', '-slice', dest='interval', action='store',default=5.0,
                        help="Specify duration of time interval observation (ex: 5.0, 10.00)")

    # threshold=10, sigma=100, alpha=0.5, beta=0.95, ewma_factor
    param_group = parser.add_argument_group('Parametric CUSUM/EWMA', 'Description here')
    param_group.add_argument('-p','-param-cusum', action='store', dest="param", 
                        help="Set detection alghorithm to parametric CUSUM/EWMA", type=bool)
    param_group.add_argument('-t','-threshold', action='store', dest="threshold", 
                        help="Description threshold here", type=int)
    param_group.add_argument('-v','-variance', action='store', dest="sigma", 
                        help="Description variance here", type=int)
    param_group.add_argument('-a','-alpha', action='store', dest="alpha", 
                        help="Description alpha here", type=float)
    param_group.add_argument('-b','-beta', action='store', dest="beta", 
                        help="Description beta here", type=float)
                    
   # TODO: Non parametric CUSUM/EWMA parameter input
   # free parameter: tau_s, t_o, delay, 
   # nparam_group = parser.add_argument_group('Non parametric CUSUM/EWMA', 'Description here')
   # nparam_group.add_argument('-np','-nonparam-cusum', action='store', dest="nparam",
   #                     help="Set detection alghorithm to non-parametric CUSUM/EWMA",type=bool)

    # Parse from keyboard
    args = parser.parse_args()
    plot =  Graph()
    if args.file is None:
        source = str(args.interface)
        analyzer = TrafficAnalyzer(source, plot, live_capture=True)
    else:
        source = str(args.file)
        analyzer = TrafficAnalyzer(source, plot)

    analyzer.start()
    

if __name__ == "__main__":
    main()
