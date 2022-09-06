from scapy.all import *
import os


class Interceptor:
    def __init__(self, *args, **kwargs):
        self.ch_range = range(1, 12)  # todo utils
        self.interface = "wlan0" # todo set as conf also
        self._channel_sniff_timeout = 5  # todo utils

    def _set_channel(self, ch_num):
        os.system("iw dev %s set channel %d" % (self.interface, ch_num))

    def _ap_scan_cb(self, pkt):
        if pkt.haslayer(Dot11):
            try:
                if "ff:ff:ff" not in pkt.addr1 and "ff:ff:ff" not in pkt.addr2: # TODO ff:ff:ff into utils
                    elt = pkt[Dot11Elt]
                    if len(elt.info) == 0:
                        return
                    ssid = print(elt.info)
                    src_device_mac = pkt.addr1
                    print(pkt.addr2)
                    ap_mac = pkt.addr3
            except:
                pass

    def _scan_for_aps(self):
        for ch in self.ch_range:
            print(f"setting and scanning channel {ch}...")
            self._set_channel(ch)
            sniff(prn=self._ap_scan_cb, iface=self.interface, timeout=self._channel_sniff_timeout)





if __name__ == "__main__":
    i = Interceptor()
    i._scan_for_aps()
