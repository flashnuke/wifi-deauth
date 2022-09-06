import time
import os
import random
def channel_hopper():
    while True:
        try:
            channel = random.randrange(1,12)
            os.system("iw dev %s set channel %d" % ("wlan0", channel))
            time.sleep(1)
        except KeyboardInterrupt:
            break

channel_hopper()
