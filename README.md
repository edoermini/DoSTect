# DoSTect

DoSTect is a tool created to detect SYN flooding attacks in two **operating modes** : **online** (in which it observes the incoming and outgoing packets in real time) and **offline** (in which it observes a **pcap** file containing a passed scan of the network traffic).

In both modes the logic behind the detection is based on a type of a statistical method called **CUSUM** (Cumulative Sum).
The CUSUM algorithm belongs to the family of change point detection algorithms that are based on hypothesis testing, as its name implies, it involves a cumulative sum of a statistical data records added to some weights and when the sum exceeds a certain threshold an anomaly is detected. 

This statistical method is used and implemented in two different ways that are **parametric CUSUM** and **non-parametric CUSUM**, both explained below.

The tool provides also the possibility to store the measurements done in an **InfluxDB** database, in which those values are plotted on a dedicated dashboard.

# Parametric CUSUM

For this type of CUSUM, we based our implementation on [1] in which 2 algorithms are presented: adaptive threshold algorithm, Cumulative Sum (CUSUM) algorithm.
For our aims only the second algorithm was implemented.

In this type of CUSUM we use as metric the number of SYN packets in a given time interval, that doesn't make the time series stationary in first place, but inside this CUSUM implementation we make the series stationary computing this difference:

<p align="center">
    <img width=150 src=https://render.githubusercontent.com/render/math?math={\widetilde{x}}_{n}=x_{n}-\overline{\mu}_{n-1}>
</p>


where ![formula](https://render.githubusercontent.com/render/math?math=x_{n}) is the number of SYN packets in the nth time interval, and ![formula](https://render.githubusercontent.com/render/math?math=\overline{\mu}_{n}) is an estimate of the mean rate at time n, which is computed using an exponential weighted moving average.

The volume is computed with the following formula:
<p align="center">
    <img width=400 src=https://render.githubusercontent.com/render/math?math=g_{n}=\left[g_{n-1}+\frac{\alpha\overline{\mu}_{n-1}}{\sigma^{2}}\cdot\left(x_{n}-\overline{\mu}_{n-1}-\frac{\alpha\overline{\mu}_{n-1}}{2}\right)\right]^{+}>
</p>

where ![formula](https://render.githubusercontent.com/render/math?math=\alpha) is the amplitude percentageparameter, which intuitively corresponds to the most probablepercentage of increase of the mean rate after a change (attack) has occurred, and ![formula](https://render.githubusercontent.com/render/math?math=\sigma^{2}) is the variance of Gaussians random variables used to model the variations of incoming SYN traffic (a value derivated from a classical CUSUM equation).

If the volume computed goes beyond a given fixed threshold an alarm is raised.



# Non-Parametric CUSUM

For this type of CUSUM, we based our implementation on [2].

The detection is done by measuring over time, this ratio:

<p align="center">
    <img width=130 src=https://render.githubusercontent.com/render/math?math=x_{n}=\frac{{S}_{n}-{A}_{n}}{{S}_{n}}>
</p>


where ![formula](https://render.githubusercontent.com/render/math?math={S}_{n}) denotes the number of SYN packets and ![formula](https://render.githubusercontent.com/render/math?math={A}_{n}) corresponds to SYN/ACK packets.
  
This allows to make the time series stationary because, during normal use of the network, the ratio tends to be zero (i.e. the number of incoming SYN packets equals that of outgoing ACK packets) while, during a SYN flooding attack, the ratio tends to increase, as they have more inbound SYN packets than outbound SYN/ACKs.

This detection method consists of three main modules:

1. **Outlier Processing**

    Its aim is to improve the accuracy of the detection (and to avoid false positive cases) by __discarding__ outliers values that go beyond a fixed threshold and treat them as anomalous, semplifying the detection of high-intensity attacks.

2. **Data Smoothing and Transformation**

    In this module is used a sliding window containing ![formula](https://render.githubusercontent.com/render/math?math=x_{n}) values and the random sequence ![formula](https://render.githubusercontent.com/render/math?math=z_{n}) (used to update the volume) is computed using the window mean ![formula](https://render.githubusercontent.com/render/math?math=y_{n}), the last exponentially weighted moving average (EWMA) value ![formula](https://render.githubusercontent.com/render/math?math=\widetilde{\mu}_{n-1}) and the last variance value ![formula](https://render.githubusercontent.com/render/math?math=\widetilde{\sigma}_{n-1}).

    <p align="center">
        <img width=230 src=https://render.githubusercontent.com/render/math?math=z_{n}=y_{n}-\widetilde{\mu}_{n-1}-3\widetilde{\sigma}_{n-1}>
    </p>


    

3. **Adaptive CUSUM Detection**

    In this module the volume is updated using the random sequence z and according to that value either, if the z value is equal or less than 0, the exponentially weighted moving average and the variance are computed or, if z if greater than 0, the detection threshold is updated. In case the detection threshold is updated a threshold crossing control is made.

# Description

The project is divided in the following parts:

* **dostect.py**: is the main file
* **/core**:
    * **detectors.py**: contains CUSUM detection algorithms
    * **forecasting.py**: conta ins SES forecasting algorithm
    * **graph.py**: contains influxdb plotting class
    * **traffic.py**: contains traffic analysis classes
    * **utils.py**: contains general utilities
* **/config/influxdb**:
     * **config.ini**: contains influxdb's configuration options

# Usage
Install dependencies: 
```
$ pip install -r requirements.txt
```

Run program, the options are listed below:
```
usage: dostect.py [-h] (-i INTERFACE | -f FILE .pcap/.pcapng) [-s INTERVAL] [-p [PARAM]]
                  [-g [GRAPH]] [-t THRESHOLD] [-a ADDRESS] [-v [VERBOSE]]

DoSTect allow to detect SYN flooding attack with Parametric/Non Parametric CUSUM change point
detection

optional arguments:
  -h, --help            show this help message and exit
  -i INTERFACE, --interface INTERFACE
                        Network interface from which to perform live capture
  -f FILE .pcap/.pcapng, --file FILE .pcap/.pcapng
                        Packet capture file
  -s INTERVAL, --slice INTERVAL
                        Specify duration of time interval observation in seconds (e.g: 5)
  -p [PARAM], --parametric [PARAM]
                        Flag to set CUSUM Parametric mode
  -g [GRAPH], --graph [GRAPH]
                        Activate influxDB data sender: requires --interface
  -t THRESHOLD, --threshold THRESHOLD
                        Threshold detection value for CUSUM Parametric mode
  -a ADDRESS, --address ADDRESS
                        IPv4 address of attacked machine for PCAP capture: requires --file
  -v [VERBOSE], --verbose [VERBOSE]
                        Flag to set verbose output mode
```
If you need influxdb plotting you must configure first the influxdb options in the `config/influxdb/config.ini` where:
```
[influx2]
url="influxdb service url:port"
org="organization id"
token="influx db token created with read/write rights"
timeout="api request timeout in ms"
verify_ssl="True if there is necessity to verify ssl connection, False otherwise"
```
# References
[1]: [Application of anomaly detection algorithms for detecting SYN flooding attacks, V.A. Siris; F. Papagalou, IEEE, 2005](https://ieeexplore.ieee.org/document/1378372)

[2]: [A nonparametric adaptive CUSUM method and its application in source-end defense against SYN flooding attacks, Ming YU, Wuhan University Journal of Natural Sciences, 2011](https://link.springer.com/article/10.1007/s11859-011-0772-5)
