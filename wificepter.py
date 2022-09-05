from scapy.all import *

def foo(frame):
    if frame.haslayer(Dot11):
        frame.show()

sniff(prn=foo)