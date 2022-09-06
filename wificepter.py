from scapy.all import *

class Interceptor:
    def __init__(

def foo(frame):
    if not frame.haslayer(Dot11):
        return
    try:
        if  "ff:ff:ff" not in frame.addr1 and "ff:ff:ff" not in frame.addr2:
            elt = frame[Dot11Elt]
            if len(elt.info) == 0:
                return
            ssid = print(elt.info)
            src_device_mac = frame.addr1
            print(frame.addr2)
            ap_mac = frame.addr3
    except:
        pass
interface = "wlan0" # todo

sniff(prn=foo, iface=interface)
