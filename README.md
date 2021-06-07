[![ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/Q5Q24VZ2M)


![example branch parameter](https://github.com/kampfhamster309/osxharvey/actions/workflows/python-app.yml/badge.svg?branch=main) 

# OsxHarvey 

The *Big White Rabbit* OsxHarvey is a small tool/Wifi-Sniffer to grab all the data.

Being a rabbit, Harvey hops from wifi-channel to wifi-channel to make sure he doesn't 
miss anything.

Harvey is intended to be used by security professionals for LEGAL purposes.

## This package is in pre-Alpha and therefore still under construction

### Requirements:

OsxHarvey is tested and built on Python3.9 and macOS Big Sur, it uses scapy under the hood and needs to be run with sudo privileges.

### Installation:

```commandline
pip install osxharvey
```

### Usage:

OsxHarvey can either be used in code or from the command line.

#### CLI:
```commandline
osxharvey
```

#### Code:

```python
from osxharvey import OsxHarvey

# Following params are default values

bwr = OsxHarvey(
        iface="en0", rounds=1,
        ch_from=1, ch_to=15,
        devices=False, ssids=False,
        probes=False, vendors=False,
        verbose=False
    )

# Params:

"""
:param str iface: Interface to sniff on
:param int rounds: How many times to go through the Wifi channels
:param int ch_from: Wifi channel to start sniffing on
:param int ch_to: Wifi channel to end sniffing on
:param bool devices: Write collected device/manufacturer combinations to file
:param bool ssids: Write detected ssids to file
:param bool probes: Write collected probe requests to file
:param bool vendors: Write list of unique detected vendors to file
:param bool verbose: Toggles verbose output
"""

# Disconnets the Wifi, enables monitor mode and starts scanning
# returns a dictionary with the collected data
results = bwr.start_scanning()

```

## TODO:
* ~~Enable installation as command line tool~
* Expand testing
  * ~~Setup automated testing through github~~
* Extend functionality
* Generate proper documentation
* Think about GUI
* Think about portability