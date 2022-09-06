import time
import os
import random
def channel_hopper():
    while True:
        try:
            channel = random.randrange(1,12)
            time.sleep(1)
        except KeyboardInterrupt:
            break

channel_hopper()
