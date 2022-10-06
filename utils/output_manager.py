import os
import sys

_DEVNULL = open(os.devnull, "w")
_ORIG_STDOUT = sys.stdout
_CLEAR_LINE = "\x1b[1A\x1b[2K"
DELIM = 80 * "="
BANNER = """
 __      __ __  _____ __         _________                          __   __     
/  \    /  \__|/ ____\__|        \    __  \   ____  _____    __ ___/  |_|  |__  
\   \/\/   /  \   __\|  |  ______ |  |  \  \/ ___ \ \  __ \ |  |  \   __|  |  \ 
 \        /|  ||  |  |  | /_____/ |  |__/  /\  ___/ | |__\ \|  |  /|  | |   Y  \\
  \__/\__/ |__||__|  |__|        /________/  \_____/_______/ ____/ |__| |___|__/ 
"""

def invalidate_print():
    global _DEVNULL
    sys.stdout = _DEVNULL


def printf(text):
    global _ORIG_STDOUT, _DEVNULL
    sys.stdout = _ORIG_STDOUT
    print(text)
    sys.stdout = _DEVNULL


def clear_line(lines=1):
    printf(lines * _CLEAR_LINE)
