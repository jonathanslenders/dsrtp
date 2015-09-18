"""
Simple front-end to read captured packets from one of:

- PCAP file
- ...

decrypt/unprotect packets idenfitied as SRTP to RTP and write as one of:

- PCAP file
- ...

Everything hard is done by:

- `dpkt <https://github.com/kbandla/dpkt>`_ to read and write packets
- `libsrtp <https://github.com/cisco/libsrtp>`_ to decrypt/unprotect SRTP
  packets.

Use it like e.g. this to decrypt SRTP packets in PCAP file to RTP packets in
PCAP file:

.. code::python

    import dsrtp
    
    material = 'hex-encoding-of-dtls-keying-material'.decode('hex') 
    
    with dsrtp.SRTP(material) as srtp_ctx, \
         open('/path/to/srtp.pcap', 'rb') as srtp_pcap, \
         open('/path/to/rtp.pcap', 'rb') as rtp_pcap,:
        pkts = dsrtp.read_packets(srtp_pcap)
        decrypted_pkts = decrypt_srtp_packet(srtp_ctx, pkts)
        dsrtp.write_packets(decrypted_pkts)

"""
__version__ = '0.1.0'

__all__ = [
    'is_srtp_packet',
    'decrypt_srtp_packet',
    'decrypt_srtp_packets',
    'read_packets'
    'write_packets'
    'SRTP',
    'SRTPError',
]

import logging

import dpkt

from .ext import SRTP, SRTPError


logger = logging.getLogger(__name__)


def is_udp_packet(packet):
    """
    Determines if a `dpkt.Packet` is UDP.
    """
    return (
            isinstance(packet.data, dpkt.ip.IP) and
            isinstance(packet.data.data, dpkt.udp.UDP)
        )


def is_srtp_packet(packet):
    """
    Determines if a `dpkt.Packet` is SRTP.
    """
    if not is_udp_packet(packet):
        return False
    ip = packet.data
    udp = ip.data
    rtp = dpkt.rtp.RTP(udp.data)
    return rtp.pt < 64 or 96 <= rtp.pt


def is_srtcp_packet(packet):
    """
    Determines if a `dpkt.Packet` is SRTCP.
    """
    if not is_udp_packet(packet):
        return False
    ip = packet.data
    udp = ip.data
    rtp = dpkt.rtp.RTP(udp.data)
    return 64 <= rtp.pt and rtp.pt < 96


def decrypt_srtp_packet(srtp, packet):
    """
    Decrypts one SRTP `dpkt.Packet`.
    """
    ip = packet.data
    udp = ip.data
    udp.data = srtp.unprotect(udp.data)
    udp.ulen = len(udp.data)
    packet.unpack(packet.pack())
    return packet


def decrypt_srtcp_packet(srtp, packet):
    """
    Decrypts one SRTCP `dpkt.Packet`.
    """
    ip = packet.data
    udp = ip.data
    udp.data = srtp.unprotect_control(udp.data)
    udp.ulen = len(udp.data)
    packet.unpack(packet.pack())
    return packet


def decrypt_packets(
        srtp,
        packets,
        packet_filter=None,
        unknown='pass',
        excluded='drop',
        malformed='drop',
        decrypt_srtp=True,
        decrypt_srtcp=True,
    ):
    """
    Decrypts SRTP and SRTCP `dpkt.Packet`s.
    """
    drop_excluded = excluded == 'drop'
    drop_unknown = unknown == 'drop'
    drop_malformed = malformed == 'drop'
    raise_malformed = malformed == 'raise'
    if packet_filter is None:
        packet_filter = lambda frame: True
    for i, (ts, packet) in enumerate(packets):
        if not packet_filter(packet):
            if drop_excluded:
                logger.debug('dropping excluded packet #%d', i + 1)
                continue
        elif decrypt_srtp and is_srtp_packet(packet):
            try:
                packet = decrypt_srtp_packet(srtp, packet)
            except SRTPError, ex:
                if drop_malformed:
                    logger.debug('dropping malformed srtcp packet #%d', i + 1, exc_info=ex)
                    continue
                if raise_malformed:
                    raise
                logger.debug('keeping malformed srtcp packet #%d', i + 1, exc_info=ex)
        elif decrypt_srtcp and is_srtcp_packet(packet):
            try:
                packet = decrypt_srtp_packet(srtp, packet)
            except SRTPError, ex:
                if drop_malformed:
                    logger.debug('dropping malformed srtcp packet #%d', i + 1, exc_info=ex)
                    continue
                if raise_malformed:
                    raise
                logger.debug('keeping malformed srtcp packet #%d', i + 1, exc_info=ex)
        else:
            if drop_unknown:
                logger.debug('dropping unknown packet #%d', i + 1)
                continue
        yield ts, packet


def read_packets(fo, frame_type=dpkt.ethernet.Ethernet):
    """
    Reads `dpkt.Packet`s from a PCAP file.
    """
    pcap = dpkt.pcap.Reader(fo)
    for ts, buf in pcap:
        yield ts, frame_type(buf)


def write_packets(fo, packets):
    """
    Saves `dpkt.Packet`s to a PCAP file.
    """
    pcap = dpkt.pcap.Writer(fo)
    for ts, packet in packets:
        pcap.writepkt(packet, ts)
