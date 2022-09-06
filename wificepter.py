from scapy.all import *

def foo(frame):
    if not frame.haslayer(Dot11):
        return
     #   if frame.haslayer(Dot11Elt):
      #      netname = frame[Dot11Elt].info.decode()
       #     if True or "ff:ff:ff" not in frame[Dot11].addr1 and "ff:ff:ff" not in frame[Dot11].addr2:
#                print(netname) 
 #               print(frame[Dot11].addr1)
  #              print(frame[Dot11].addr2)
   #             print(frame[Dot11].addr3)
    #    else:
     #       return
      #      frame.show()
    #while elt and elt.ID != 0:
     #   elt.show()
       # elt = elt.payload[Dot11Elt]
    try:
        if  "ff:ff:ff" not in frame.addr1 and "ff:ff:ff" not in frame.addr2:
            elt = frame[Dot11Elt]
            if len(elt.info) == 0:
                return
            print(elt.info)
            print(frame.addr1)
            print(frame.addr2)
            print(frame.addr3)
    except:
        pass
interface = "wlan0" # todo

sniff(prn=foo, iface=interface)
