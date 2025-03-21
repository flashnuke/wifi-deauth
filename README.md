![image](https://user-images.githubusercontent.com/59119926/196630355-9edfa98f-7c97-4555-b882-73a0cc87744c.png)
</br>
A DoS attack that disconnects all devices from a target wifi network.
* The network's password is not required
* Tested on Kali NetHunter (Snapshot at the bottom)


**IMPORTANT** </br>
In some occasions, network APs might operate on both 5GHz and 2.4GHz under the same BSSID/SSID name. <br>
In order to truly bring the AP down, I usually run simultaneously two de-authers using 2 network interfaces: one for 2.4GHz and one for 5GHz. </br>
| Bandwidth | Channel range |
|----------|---------------|
| 2.4 GHz   | 1 <--> 14     |
| 5 GHz     | 35 <--> 165   |

## How it works
<img src="https://github.com/flashnuke/wifi-deauth/assets/59119926/26f75cce-0484-4949-840e-d23fa976ff9b" width="480">

The program iterates over all possible channels, and by sniffing `802.11` packets it determines which access points are available. </br>
After the attacker chooses a target access point to attack, the program:
1. Continously sends spoofed deauthentication packets using broadcast mac address as the destination
2. Starts sniffing for clients that are connected to the AP by filtering for certain 802.11 packet frames and sending spoofed deauthentication packets to those clients in addition to the broadcast address


# Usage
#### Installing on the system
```bash
git clone https://github.com/flashnuke/wifi-deauth.git
cd wifi-deauth
sudo pip3 install .
sudo wifi-deauth -i <iface>
```

#### Running without installing 
```bash
git clone https://github.com/flashnuke/wifi-deauth.git
cd wifi-deauth
sudo pip3 install -r requirements.txt # install requirements manually
cd wifi_deauth
sudo python3 wifi_deauth.py -i <iface>
```

### Usage notes
*  `<iface>` is the name of the network interface (i.e `wlan0` or `eth0`) that supports packet injection
* `--deauth-all-channels` - try this option if the attack doesn't work (see more in [Optional Arguments](https://github.com/flashnuke/wifi-deauth/tree/main?tab=readme-ov-file#optional-arguments))
* `--autostart` is good for automation - first make sure that only 1 access point is found, you can use filters (bssid, ssid, channels, etc...) to ensure that
* The initial iteration over all channels might take a minute or two (depends on how many bands the interface supports)

### Optional arguments
* `--deauth-all-channels` - send de-auth packets on all allowed channels (or all custom channels if `--channels` is set) iteratively, effective against access points that switch to a different channel as a protection mechanism
* `--ssid <name>` - filter for a specific SSID by a case-insensitive substring (this should shorten the channel-scanning duration), whitespaces should be passed with an escape character (i.e -> `new\ york`)
* `--bssid <addr>` - filter for a specific BSSID (the access point's MAC address), case in-sensitive
* `--autostart` - start the de-auth loop automatically, works only when one access point is found
* `--channels <ch1,ch2>` - scan for specific channels only, otherwise all supported channels will be scanned
* `--clients <m_addr1,m_addr2>` - target only specific clients to disconnect from the AP, otherwise all connected clients will be targeted (note: using this option disables deauth broadcast)
* `--debug` - enable debug prints
* `--kill` (or run `sudo systemctl stop NetworkManager`) - kill NetworkManager service which might interfere with the attack
* `--skip-monitormode` - enable monitor mode manually (otherwise the program does it automatically)

### Misc notes
* Setting custom client mac addresses (`--clients`) is not suggested, as some clients might reconnect using a random MAC address which is different than the one set
* Check `ifconfig` to find the interface nickname
* Works for 2.4GHhz and 5Ghz

### Requirements
* Linux OS
* A network adapter that supports monitor mode and packet injection
* Scapy library (listed in `requirements.txt`)

# Deadnet & other projects
Feel free to check out my other projects, the most recent one being [mod-rootkit](https://github.com/flashnuke/mod-rootkit), which is a Linux kernel-level rootkit designed to hide files, processes, and network activity.

There's another project ([deadnet](https://github.com/flashnuke/deadnet)) that performs a DoS attack on networks, which requires credentials but quite effective nonetheless.

# Disclaimer

This tool is only for testing and can only be used where strict consent has been given. Do not use it for illegal purposes! It is the end user’s responsibility to obey all applicable local, state and federal laws. I assume no liability and am not responsible for any misuse or damage caused by this tool and software.

Distributed under the GNU License.
