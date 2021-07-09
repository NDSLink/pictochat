# Run this with mypy when testing!
# Credit to https://github.com/Thesola10/PictoChat/blob/master/pcpa/src/decoder.c for most of the important info used here
from typing import Final
from socket import socket
from pylibpcap.pcap import sniff

RADIOTAP_OFFSET: Final[int] = 64
PICTOCHAT_OFFSET: Final[int] = 36
PICTOCHAT_NORMAL_PAYLOAD: Final[int] = 160
PICTOCHAT_MAX_PAYLOAD: Final[int] = 255
MAX_PACKETS_PER_MESSAGE: Final[int] = 512
MAX_PACKET_LEN: Final[int] = 1024
NINTENDO_MAC_ADDRESS_PREFIX: Final[bytearray] = bytearray([0x00, 0x09, 0xbf])
RSSI_PACKET_COUNT: Final[int] = 40

def is_packet_pictochat(buf):
    if buf[RADIOTAP_OFFSET + 10:RADIOTAP_OFFSET + 10 + 3] == NINTENDO_MAC_ADDRESS_PREFIX:
        return True
    else:
        return False

for plen, t, buf in sniff("wlan0", count=-1):
    if is_packet_pictochat(plen, t, buf):
        raise NotImplementedError("Packet comes from Pictochat, but support is not fully implemented")