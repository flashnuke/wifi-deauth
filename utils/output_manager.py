import os
import sys

_DEVNULL = open(os.devnull, "w")
_ORIG_STDOUT = sys.stdout
_CLEAR_LINE = "\x1b[1A\x1b[2K"
DELIM = 80 * "="

_TRESET = '\033[0m'
_TBOLD = '\033[1m'
_TRED = '\033[31m'


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

BANNER = f"""
{_TBOLD}{_TRED} __      __ {_TRESET}__  _____ __         {_TBOLD}{_TRED}_________{_TRESET}                          __   __     
{_TBOLD}{_TRED}/  \    /  \\{_TRESET}__|/ ____\__|        {_TBOLD}{_TRED}\    __  \{_TRESET}  _____ ______   __ ___/  |_|  |__  
{_TBOLD}{_TRED}\   \/\/   /{_TRESET}  \   __\|  |  ______ {_TBOLD}{_TRED}|  |  \  \{_TRESET}/ ___ \\\  __ \ |  |  \   __|  |  \ 
{_TBOLD}{_TRED} \        /{_TRESET}|  ||  |  |  | /_____/ {_TBOLD}{_TRED}|  |__/  /{_TRESET}\  ___/| |__\ \|  |  /|  | |   Y  \\
{_TBOLD}{_TRED}  \__/\__/ {_TRESET}|__||__|  |__|        {_TBOLD}{_TRED}/________/{_TRESET}  \____/|______/ ____/ |__| |___|__/ 
"""
