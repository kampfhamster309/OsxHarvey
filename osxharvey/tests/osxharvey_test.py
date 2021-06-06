import unittest
from scapy.layers.dot11 import Dot11Beacon, Dot11, Dot11ProbeReq, Dot11Elt
from scapy.packet import fuzz
from osxharvey import OsxHarvey


class TestOsxHarvey(unittest.TestCase):
    dot11_layer = Dot11(
        addr1=b'ff:ff:ff:ff:ff:ff',
        addr2=b'aa:bb:cc:11:22:33',
        addr3=b'dd:ee:ff:11:22:33',
    )

    def test_parser_dot11probereq(self):
        packet = fuzz(Dot11() / Dot11ProbeReq() / Dot11Elt())
        bwr = OsxHarvey()
        bwr.pktIdentifier(packet)
        length = len(bwr.probe_req)
        self.assertEqual(length, 1)

    def test_parser_dot11beacon(self):
        packet = fuzz(Dot11() / Dot11Beacon() / Dot11Elt())
        bwr = OsxHarvey()
        bwr.pktIdentifier(packet)
        length = len(bwr.ssids_list)
        self.assertEqual(length, 1)


if __name__ == '__main__':
    unittest.main()
