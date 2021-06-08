from influxdb_client.client.write_api import SYNCHRONOUS
from influxdb_client.client import write_api
from influxdb_client.client.influxdb_client import BucketsApi
from threading import Timer
import influxdb_client
from influxdb_client import *
import heapq
import threading
import os
import sys
import signal

class Graph():

    def __init__(self, config_file, bucket_name="dostect", time_interval=1):

        """
        Called by traffic catching classes.
        Connect to influxdb2 throughout a given config.ini file.
        Provides a shared priority queue for TCP volume computed by detection algorithms
        and retrieve every time_interval sec these data to create plotting point to write in bucket_name

        :param config_file: path to config file (.ini)
        :param bucket_name: influxdb bucket's name
        :param time_interval: time interval provided by input
        """

        self.interval = time_interval
        self.bucket_name = bucket_name
        self.org = ""
        self.write_api = None
        self.tcp_queue = []
        self._timer = None
        self.__stopped = False

        #Register handler for SIGINT
        signal.signal(signal.SIGINT, self.__signalHandling)

        client = None
        try:
            # Load influx configuration from .ini file: retrieve HOST:PORT, ORG ID, ACCESS TOKEN
            client = influxdb_client.InfluxDBClient.from_config_file(config_file=config_file)
        except:
            print("[Graph mode] - Error while connecting to influxdb instance: check your service or .ini file!")
            exit(1)
            
        self.org = client.org

        # Creating buckets API for buckets access
        bucket = client.buckets_api()

        # Checks if bucket bucket_name already exists, else create it
        if bucket.find_bucket_by_name(self.bucket_name) is None:
            bucket.create_bucket(bucket_name=self.bucket_name)
            print("[Graph mode] - Bucket " + self.bucket_name + " created!")
                    
        # Creating write API for points creation
        self.write_api = client.write_api(write_options=SYNCHRONOUS)
  
        # Start periodical writing thread
        self.__run()

    def __write_data(self):
        """
        Writes into influxdb data found into internal shared priority queue
        """

        # Check if there is volume values to write
        while len(self.tcp_queue) > 0:

            # Retrieve timestamp,values from <timestamp:[data]>
            timestamp, values = heapq.heappop(self.tcp_queue)

            # Create point with [data] and write it to bucket bucket_name
            p_syn = influxdb_client.Point("data_interval")

            for label, value in values:
                p_syn.field(label, value)

            try:
                # Writing point to influxdb
                self.write_api.write(bucket=self.bucket_name, org=self.org, record=p_syn)
            except: 
                  #TODO: fix this case                  
                  print("[Graph mode] - Error while writing to influxdb instance: check your service or .ini file!")
                
                  self.__stopped = True
                  sys.exit(1)
                  

    def update_data(self, data: tuple, timestamp: int):
        """
        Insert data (TCP volume,threshold, SYN volume, ACK volume) into shared priority queue

        :param data: a tuple of data to add, each element in data is a tuple of two elements (label:str, value:Any)
        :param timestamp: the time of record
        """

        heapq.heappush(self.tcp_queue, (timestamp, data))
       
    def __signalHandling(self, signal_number, frame):
        """
        Closes the thread if a signal is reached

        :param signal_number:
        :param frame:
        """
        self.__stopped = True
        exit(0)

    def __run(self):
        """
        Calls self.__write_data() periodically in a thread to write data
        saved into internal shared priority queue asynchronously
        """

        if not self.__stopped:
            threading.Timer(self.interval, self.__run).start()
        else: sys.exit()

        self.__write_data()
    



        

  
