from OuiLookup import OuiLookup
from scapy.layers.dot11 import Dot11, Dot11ProbeReq, Dot11ProbeResp, Dot11Beacon
from scapy.packet import Packet

from osxharvey.event import subscribe


def __scan_Dot11(self, pkt: Packet) -> None:
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


def __scan_Dot11ProbeReq(self, pkt: Packet) -> None:
    """
    Extracts the MAC and name of the net from collected Dot11ProbeRequests. The information is then written to
    list and, inf enabled, to file.

    :param pkt: Packet with Dot11ProbeRequest layer
    :return:
    """
    print("Running parser")
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


def __scan_Dot11ProbeResp(self, pkt: Packet) -> None:
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


def __scan_Dot11Beacon(self, pkt: Packet) -> None:
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


def setup_dot11_event_handlers() -> None:
    """
    Subscribes different handlers/parsers for different types of Dot11 layers
    """
    subscribe("Dot11", __scan_Dot11)
    subscribe("Dot11ProbeReq", __scan_Dot11ProbeReq)
    subscribe("Dot11ProbeResp", __scan_Dot11ProbeResp)
    subscribe("Dot11Beacon", __scan_Dot11Beacon)
