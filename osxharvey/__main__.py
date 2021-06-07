from .main import OsxHarvey
import sys


def main(args=None):
    harvey = """
       _
      (\\\\
       \||
     __(_";    This is Harvey, the curious rabbit
    /    \     He hops around to find all the wifi things...
   {}___)\)_
    """
    print(harvey)
    print("=" * 70)
    print("[*] First, we'll need to configure some things:")
    iface = str(input("[*] Interface to sniff on [en0]: ") or "en0")
    ch_from = int(input("[*] Wifi channel to start on [1]: ") or 1)
    ch_to = int(input("[*] Wifi channel to end sniffing on [15]: ") or 15)
    rounds = int(input("[*] How many times to go through the channels [1]: ") or 1)
    devices = str(input("[*] Write collected device/vendor combinations to file [y/N]: ") or "N")
    ssids = str(input("[*] Write collected ssids to file [y/N]: ") or "N")
    probes = str(input("[*] Write collected probe requests to file [y/N]: ") or "N")
    vendors = str(input("[*] Write list of detected vendors to file [y/N]: ") or "N")
    verbose = True

    if devices.lower() == "y":
        devices = True
    elif devices.lower() == "n":
        devices = False
    else:
        sys.exit("[!!] Invalid value for devices. Please enter either 'y' or 'n'")

    if ssids.lower() == "y":
        ssids = True
    elif ssids.lower() == "n":
        ssids = False
    else:
        sys.exit("[!!] Invalid value for ssids. Please enter either 'y' or 'n'")

    if probes.lower() == "y":
        probes = True
    elif probes.lower() == "n":
        probes = False
    else:
        sys.exit("[!!] Invalid value for probes. Please enter either 'y' or 'n'")

    if vendors.lower() == "y":
        vendors = True
    elif vendors.lower() == "n":
        vendors = False
    else:
        sys.exit("[!!] Invalid value for vendors. Please enter eiter 'y' or 'n'")

    bwr = OsxHarvey(iface=iface, rounds=rounds,
                    ch_from=ch_from, ch_to=ch_to,
                    devices=devices, ssids=ssids,
                    probes=probes, vendors=vendors, verbose=verbose)

    bwr.start_scanning()


if __name__ == '__main__':
    sys.exit(main())
