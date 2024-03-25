![image](https://user-images.githubusercontent.com/59119926/196630355-9edfa98f-7c97-4555-b882-73a0cc87744c.png)
</br>
A DoS attack that disconnects all devices from a target wifi network.
* The network's password is not required
* Tested on Kali NetHunter (Snapshot at the bottom)


**IMPORTANT** </br>
In some occasions, network APs might operate on both 5GHz and 2.4GHz under the same BSSID name. <br>
In order to truly bring the AP down, I usually run simultaneously two de-authers using 2 network interfaces: one for 2.4GHz and one for 5GHz. </br>
| Bandwidth | Channel range |
|----------|---------------|
| 2.4 GHz   | 1 <--> 14     |
| 5 GHz     | 35 <--> 165   |

## How it works
<img src="https://github.com/flashnuke/wifi-deauth/assets/59119926/7f9efac1-bb33-4bee-8b75-2aadd376d065" width="480">

The program iterates over all possible channels, and by sniffing `802.11` packets it determines which access points are available. </br>
After the attacker chooses a target access point to attack, the program:
1. Continously sends spoofed deauthentication packets using broadcast mac address as the destination
2. Starts sniffing for clients that are connected to the AP by filtering for certain 802.11 packet frames and sending spoofed deauthentication packets to those clients in addition to the broadcast address


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
* Works for 2.4GHhz and 5Ghz
* Beware that some access points have protections against this kind of attack and therefore it might not work on them

### Requirements
* Linux OS
* A network adapter that supports monitor mode and packet injection
* Scapy library (listed in `requirements.txt`)

# Deadnet
There's another [project](https://github.com/flashnuke/deadnet) that performs a DoS attack on networks, which requires [credentials](https://github.com/flashnuke/pass-generator) but quite effective nonetheless.

# Disclaimer

This tool is only for testing and can only be used where strict consent has been given. Do not use it for illegal purposes! It is the end user’s responsibility to obey all applicable local, state and federal laws. I assume no liability and am not responsible for any misuse or damage caused by this tool and software.

Distributed under the GNU License.
