from scapy.all import sniff
from scapy.layers.dot11 import Dot11Beacon, Dot11ProbeReq, Dot11, Dot11ProbeResp
from OuiLookup import OuiLookup
from tqdm import tqdm
from tqdm.utils import _term_move_up
import time
import os
import sys
import logging
import platform


class OsxHarvey:
    logger = None
    loglevel = None
    ch_from = None
    ch_to = None
    devices = None
    ssids = None
    probes = None
    vendors = None
    debug = None
    iface = None
    verbose = None
    pbar = None
    vendor_list = []
    probe_req = []
    hiddenNets = []
    unhiddenNets = []
    ssids_list = []

    def __init__(
            self,
            iface="en0",
            rounds=1,
            ch_from=1,
            ch_to=15,
            devices=False,
            ssids=False,
            probes=False,
            vendors=False,
            verbose=False,
            debug=False,
    ):
        """
        Initializes an instance of the sniffer

        :param str iface: Interface to sniff on
        :param int rounds: How many times to go through the Wifi channels
        :param int ch_from: Wifi channel to start sniffing on
        :param int ch_to: Wifi channel to end sniffing on
        :param bool devices: Write collected device/manufacturer combinations to file
        :param bool ssids: Write detected ssids to file
        :param bool probes: Write collected probe requests to file
        :param bool vendors: Write list of unique detected vendors to file
        :param bool verbose: Toggles verbose output
        :param bool debug: Toggles debug mode
        """

        self.iface = iface
        self.rounds = rounds
        self.ch_from = ch_from
        self.ch_to = ch_to
        self.devices = devices
        self.ssids = ssids
        self.probes = probes
        self.vendors = vendors
        self.debug = debug
        self.verbose = verbose
        self.__set_loglevel()
        self.__init_logger()
        if verbose:

            def verboseprint(*args, **kwargs):
                print(*args, **kwargs)

        else:
            verboseprint = lambda *a: None
        self.verboseprint = verboseprint
        self.ch_to += 1

    def __set_loglevel(self):
        """
        Sets loglevel to eiter DEBUG or ERROR
        """
        if self.debug:
            self.loglevel = logging.DEBUG
        else:
            self.loglevel = logging.ERROR

    def __init_logger(self):
        """
        Initializes the logger
        """
        handler = logging.StreamHandler(sys.stdout)
        frm = logging.Formatter(
            "[osxharvey] {asctime} - {levelname}: {message}",
            "%d.%m.%Y %H:%M:%S",
            style="{",
        )
        handler.setFormatter(frm)
        handler.setLevel(self.loglevel)
        self.logger = logging.getLogger()
        self.logger.addHandler(handler)

    def __ensure_unique(self, filename):
        """
        Ensure that entries are unique if the file already exists. This is intended to combine data collected over
        multiple occasions without duplications.

        :param filename: Name of file to check for duplicate entries
        :return:
        """
        if os.path.exists(filename):
            file_to_clean = f"_to_clean_{filename}"
            os.rename(filename, file_to_clean)
            lines_seen = set()
            outfile = open(filename, "w")
            for line in open(file_to_clean, "r"):
                if line not in lines_seen:
                    outfile.write(line)
                    lines_seen.add(line)
            outfile.close()
            os.remove(file_to_clean)

    def pktIdentifier(self, pkt):
        """
        Callback function for the sniffer. Calls different parsers as required.

        :param pkt: Sniffed packet
        :return:
        """
        if pkt.haslayer(Dot11Beacon):
            self.__scan_Dot11Beacon(pkt)
        if pkt.haslayer(Dot11ProbeResp):
            self.__scan_Dot11ProbeResp(pkt)
        if pkt.haslayer(Dot11ProbeReq):
            self.__scan_Dot11ProbeReq(pkt)
        if pkt.haslayer(Dot11):
            self.__scan_Dot11(pkt)

    def __scan_Dot11(self, pkt):
        """
        Extracts MAC address from Dot11 packet and queries OuiLookup for vendor information. Writes the collected
        information to list and, if enabled, to file.

        :param pkt: Packet with Dot11 layer
        :return:
        """
        wifiMAC = pkt.getlayer(Dot11).addr2
        if wifiMAC is not None:
            vendor = OuiLookup().query(wifiMAC)
            if vendor not in self.vendor_list:
                if self.devices:
                    with open("devices.txt", "a") as file:
                        file.write(f"{vendor}\n")
                if self.verbose:
                    self.__print_over_pbar(
                        f"[+] New Vendor/Device Combination: {vendor}"
                    )
                self.vendor_list.append(vendor)

    def __scan_Dot11ProbeReq(self, pkt):
        """
        Extracts the MAC and name of the net from collected Dot11ProbeRequests. The information is then written to
        list and, inf enabled, to file.

        :param pkt: Packet with Dot11ProbeRequest layer
        :return:
        """
        netName = pkt.getlayer(Dot11ProbeReq).info.decode("utf-8", errors="ignore")
        wifiMAC = None
        if pkt.haslayer(Dot11):
            wifiMAC = pkt.getlayer(Dot11).addr2
        if netName not in self.probe_req:
            self.probe_req.append(netName)
            if wifiMAC is not None:
                if self.verbose:
                    self.__print_over_pbar(
                        f"[+] Detected new probe request: {netName} from {wifiMAC}"
                    )
                if self.probes:
                    with open("probes.txt", "a") as probefile:
                        probefile.write(f"{wifiMAC} -> {netName}\n")
            else:
                if self.verbose:
                    self.__print_over_pbar(f"[+] Detected new probe request: {netName}")
                if self.probes:
                    with open("probes.txt", "a") as probefile:
                        probefile.write(f"unknown -> {netName}\n")

    def __scan_Dot11ProbeResp(self, pkt):
        """
        Tries to extract the name of a network previously detected as hidden from a Dot11ProbeResponse

        :param pkt: Packet with Dot11ProbeResponse layer
        :return:
        """
        addr2 = pkt.getlayer(Dot11).addr2
        if (addr2 in self.hiddenNets) and (addr2 not in self.unhiddenNets):
            netName = pkt.getlayer(Dot11ProbeResp).info.decode("utf-8", errors="ignore")
            if self.verbose:
                self.__print_over_pbar(
                    f"[+] Decloaked hidden SSID {netName} with MAC {addr2}"
                )
            if self.ssids:
                with open("decloaked.txt", "a") as decloaked_file:
                    decloaked_file.write(f"{netName} -> {addr2}\n")
            self.unhiddenNets.append(addr2)

    def __scan_Dot11Beacon(self, pkt):
        """
        Extracts SSID and MAC from a Dot11Beacon frame. The collected data is then written to list and, if enabled,
        to file.

        :param pkt: Packet with Dot11Beacon frame
        :return:
        """
        ssid_info = pkt.getlayer(Dot11Beacon).info.decode("utf-8", errors="ignore", )
        if ssid_info not in self.ssids_list:
            addr2 = pkt.getlayer(Dot11).addr2
            if self.verbose:
                self.__print_over_pbar(f"[+] Found new SSID {ssid_info} -> {addr2}")
            if self.ssids:
                with open("ssids.txt", "a") as ssidsf:
                    ssidsf.write(f"{ssid_info} -> {addr2}\n")
            self.ssids_list.append(ssid_info)
        if pkt.getlayer(Dot11Beacon).info.decode("utf-8", errors="ignore") == "":
            addr2 = pkt.getlayer(Dot11).addr2
            if addr2 not in self.hiddenNets:
                if self.verbose:
                    self.__print_over_pbar(f"[+] Found hidden SSID with MAC: {addr2}")
                if self.ssids:
                    with open("ssids.txt", "a") as ssid_file:
                        ssid_file.write(f"HIDDEN -> {addr2}\n")
                self.hiddenNets.append(addr2)

    def __print_over_pbar(self, message):
        """
        Helper function to print text above the progress bar

        :param message: String to print
        :return:
        """
        if self.pbar is not None:
            border = "=" * 50
            clear_border = _term_move_up() + "\r" + " " * len(border) + "\r"
            self.pbar.write(clear_border + message)
            self.pbar.write(border)
            time.sleep(0.1)

    def start_scanning(self):
        """
        Disconnects the Mac from any Wifi network, starts the scanner and returns a dict with the collected data.

        :return: Dictionary with collected data
        """
        if platform.system() != "Darwin":
            sys.exit("[!!] OsxHarvey only runs on Mac! Aborting...")
        if os.geteuid() != 0:
            sys.exit(
                "[!!] OsxHarvey uses scapy under the hood and therefore needs sudo privileges to run."
            )
        try:
            os.system(
                f"sudo /System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current"
                f"/Resources/airport -z"
            )
            self.verboseprint(
                f"[*] Starting scanning: {self.rounds} rounds through {self.ch_to - self.ch_from} Wifi channels\n"
            )
            for rounds in range(self.rounds):

                self.pbar = tqdm(
                    range(self.ch_from, self.ch_to),
                    desc=f"Round {rounds + 1}/{self.rounds}: ",
                    leave=False,
                )
                for channel in self.pbar:
                    os.system(
                        f"sudo /System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current"
                        f"/Resources/airport -c{channel}"
                    )
                    try:
                        if self.verbose:
                            self.__print_over_pbar(
                                f"[*] Round {rounds + 1}: Sniffing on Channel {channel}"
                            )
                        sniff(
                            iface=self.iface,
                            monitor=True,
                            prn=self.pktIdentifier,
                            count=10,
                            timeout=3,
                            store=0,
                        )
                    except Exception as e:
                        self.logger.error(f"[!!] Something has gone wrong: {str(e)}")
        except Exception as e:
            self.logger.error(e)
        if self.vendors:
            self.__write_vendors()
        self.__cleanup()
        return {
            "vendors": self.vendor_list,
            "probes": self.probe_req,
            "hidden_ssids": self.hiddenNets,
            "decloaked_ssids": self.unhiddenNets,
            "ssids": self.ssids,
        }

    def __write_vendors(self):
        """
        Writes list of vendors to file

        :return:
        """
        with open("vendors.txt", "w") as vendor_file:
            for mac_vendor_list in self.vendor_list:
                for mac_vendor in mac_vendor_list:
                    for mac in mac_vendor:
                        if mac_vendor[mac] is not None:
                            vendor_file.write(mac_vendor[mac] + "\n")

    def __cleanup(self):
        """
        Performs cleanup operations after successful scan

        :return:
        """
        self.__ensure_unique("vendors.txt")
        self.__ensure_unique("devices.txt")
        self.__ensure_unique("probes.txt")
        self.__ensure_unique("decloaked.txt")
        self.__ensure_unique("ssids.txt")

