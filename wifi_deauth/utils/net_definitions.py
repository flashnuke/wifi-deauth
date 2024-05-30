from enum import Enum

BD_MACADDR = "ff:ff:ff:ff:ff:ff"


class BandType(Enum):
    T_24GHZ = "24GHZ"
    T_50GHZ = "50GHZ"


class SSID:
    def __init__(self,
                 name: str,
                 mac_addr: str,
                 band_type: BandType):
        self.name = name
        self.mac_addr = mac_addr
        self.clients = list()

        self._band_type = band_type
        self._channel_list = list()

    def add_channel(self, ch: int):
        self._channel_list.append(ch)
        self._channel_list = sorted(self._channel_list)

    def add_client(self, mac_addr: str):
        self.clients.append(mac_addr)

    @property
    def channel(self) -> int:  # return optimal channel
        return self._channel_list[len(self._channel_list) // 2] \
            if len(self._channel_list) > 1 \
            else self._channel_list[0]


def frequency_to_channel(freq: int) -> int:
    base = 5000 if freq // 1000 == 5 else 2407
    return (freq - base) // 5
