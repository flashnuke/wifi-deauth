# Wifi-Deauth
A wifi deauth attack that disconnects all devices from the target wifi access point, without the need to be connected to the network.

## How it works
This program iterates over all possible channels, and by sniffing `802.11` packets it determines which access points are available. </br>
After the attacker chooses a target access point to attack, the program:
1. Continously sends spoofed deauthentication packets using broadcast mac address as the destination
2. Starts sniffing for clients that are connected to the AP by filtering for certain 802.11 packet frames and sending spoofed deauthentication packets to those clients as well

# Usage
```bash
python3 wifi-deauth.py -i <iface>
```
### Usage notes
*  `<iface>` is the name of the network interface (i.e `wlan0` or `eth0`) that supports packet injection
* Pass `--kill` (or run `sudo systemctl stop NetworkManager`) in order to kill NetworkManager service which might interfere with the attack
* The initial iteration over all channels might take a minute or two (depends on how many bands the interface supports)
* Pass `--skip-monitormode` if you want to enable monitor mode manually (otherwise the program does it automatically)

### Misc notes
* Check `ifconfig` to find the interface nickname
* Should work for 5Ghz also, assuming the network interface supports it
* Beware that some access points have protections against this kind of attack and therefore it might not work on them

### Requirements
* Linux OS
* A network adapter that supports monitor mode and packet injection
* Scapy library (listed in `requirements.txt`)

# Disclaimer

This tool is only for testing and can only be used where strict consent has been given. Do not use it for illegal purposes! It is the end user’s responsibility to obey all applicable local, state and federal laws. I assume no liability and am not responsible for any misuse or damage caused by this tool and software.

Distributed under the GNU License.
