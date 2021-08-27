from typing import List, Union

from scapy.all import sniff
from OuiLookup import OuiLookup
from scapy.packet import Packet
from tqdm import tqdm
from tqdm.utils import _term_move_up
import time
import os
import sys
import logging
import platform

from osxharvey.dot11_packet_handler import setup_dot11_event_handlers, harvey_instance
from osxharvey.event import post_event


class OsxHarvey:
    logger: logging.Logger = None
    loglevel: int = None
    ch_from: int = None
    ch_to: int = None
    devices: bool = None
    ssids: bool = None
    probes: bool = None
    vendors: bool = None
    debug: bool = None
    iface: str = None
    verbose: bool = None
    pbar: tqdm = None
    vendor_list: List = []
    probe_req: List = []
    hiddenNets: List = []
    unhiddenNets: List = []
    ssids_list: List = []

    def __init__(
            self,
            iface: str = "en0",
            rounds: int = 1,
            ch_from: int = 1,
            ch_to: int = 15,
            devices: bool = False,
            ssids: bool = False,
            probes: bool = False,
            vendors: bool = False,
            verbose: bool = False,
            debug: bool = False,
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
        self.__init_handler()
        self.harvey_instance = self
        if verbose:

            def verboseprint(*args, **kwargs) -> None:
                print(*args, **kwargs)

        else:
            verboseprint = lambda *a: None
        self.verboseprint = verboseprint
        self.ch_to += 1

    def __init_handler(self) -> None:
        setup_dot11_event_handlers()

    def __set_loglevel(self) -> None:
        """
        Sets loglevel to eiter DEBUG or ERROR
        """
        if self.debug:
            self.loglevel = logging.DEBUG
        else:
            self.loglevel = logging.ERROR

    def __init_logger(self) -> None:
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

    def __ensure_unique(self, filename: str) -> None:
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

    def pktIdentifier(self, pkt: Packet) -> None:
        """
        Callback function for the sniffer. Publishes events for different layers for parsers to attach to.

        :param pkt: Sniffed packet
        :return:
        """
        counter = 0
        while True:
            layer = pkt.getlayer(counter)
            if layer is None:
                break
            post_event(type(layer).__name__, self, pkt)
            counter += 1

    def print_over_pbar(self, message: str) -> None:
        """
        Helper function to print text above the progress bar

        :param message: String to print
        :return:
        """
        if self.pbar is not None:
            border = "=" * 70
            clear_border = _term_move_up() + "\r" + " " * len(border) + "\r"
            self.pbar.write(clear_border + message)
            self.pbar.write(border)
            time.sleep(0.1)

    def start_scanning(self) -> dict[str, Union[list, bool]]:
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
                            self.print_over_pbar(
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
            self.write_vendors()
        self.cleanup()
        return {
            "vendors": self.vendor_list,
            "probes": self.probe_req,
            "hidden_ssids": self.hiddenNets,
            "decloaked_ssids": self.unhiddenNets,
            "ssids": self.ssids,
        }

    def write_vendors(self) -> None:
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

    def update_ouilookup_data(self) -> None:
        """
        Updates new oui lookup data from standards-oui.iee.org.
        It's not necessary to run this every time osxharvey is used, but should be run
        on occasion.
        """
        self.verboseprint("[*] Updating lookup data...")
        OuiLookup().update()
        self.verboseprint("[+] Successfully updated oui lookup data")

    def cleanup(self) -> None:
        """
        Performs cleanup operations after successful scan

        :return:
        """
        self.__ensure_unique("vendors.txt")
        self.__ensure_unique("devices.txt")
        self.__ensure_unique("probes.txt")
        self.__ensure_unique("decloaked.txt")
        self.__ensure_unique("ssids.txt")
