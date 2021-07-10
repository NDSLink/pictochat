# Run this with mypy when testing!
# Credit to https://github.com/Thesola10/PictoChat/blob/master/pcpa/src/decoder.c for most of the important info used here
from typing import Final
from socket import socket
import libpcap
from libpcap import next_ex
from libpcap import pcap_t, pkthdr
from ctypes import pointer, POINTER, c_ubyte, byref
RADIOTAP_OFFSET: Final[int] = 64
PICTOCHAT_OFFSET: Final[int] = 36
PICTOCHAT_NORMAL_PAYLOAD: Final[int] = 160
PICTOCHAT_MAX_PAYLOAD: Final[int] = 255
MAX_PACKETS_PER_MESSAGE: Final[int] = 512
MAX_PACKET_LEN: Final[int] = 1024
NINTENDO_MAC_ADDRESS_PREFIX: Final[bytearray] = bytearray([0x00, 0x09, 0xbf])
RSSI_PACKET_COUNT: Final[int] = 40

def is_packet_pictochat(buf: bytearray) -> bool:
    if buf[RADIOTAP_OFFSET + 10:RADIOTAP_OFFSET + 10 + 3] == NINTENDO_MAC_ADDRESS_PREFIX:
        return True
    else:
        return False
libpcap.config(LIBPCAP=None)
while True:
    LP_pcap = POINTER(libpcap.pcap_t)
    pcap_source = LP_pcap()
    hdr_pointer = POINTER(libpcap.pkthdr)()
    packet_data = POINTER(POINTER(c_ubyte))()
    libpcap.next(pcap_source, hdr_pointer)
    print(type(packet_data))