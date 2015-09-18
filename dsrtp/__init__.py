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

.. code:: python

    import dsrtp
    
    material = 'hex-encoding-of-dtls-keying-material'.decode('hex') 
    
    with dsrtp.SRTP(material) as ctx, \
            open('/path/to/srtp.pcap', 'rb') as srtp_pcap, \
            open('/path/to/rtp.pcap', 'wb') as rtp_pcap:
        pkts = dsrtp.read_packets(srtp_pcap)
        decrypted_pkts = decrypt_srtp_packets(ctx, pkts)
        dsrtp.write_packets(decrypted_pkts)

"""
__version__ = '0.2.0'

__all__ = [
    'is_srtp_packet',
    'is_srctp_packet',
    'decrypt_srtp_packet',
    'decrypt_srtcp_packet',
    'decrypt_packets',
    'read_packets'
    'write_packets'
    'KeyingMaterial',
    'SRTPPolicies',
    'SRTPPolicy',
    'SRTP',
    'SRTPError',
]

import collections
import logging
import struct

import dpkt

from .ext import KeyingMaterial, SRTPPolicies, SRTPPolicy, SRTP, SRTPError


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
    return rtp.version == 2 and (rtp.pt < 64 or 96 <= rtp.pt)


def is_srtcp_packet(packet):
    """
    Determines if a `dpkt.Packet` is SRTCP.
    """
    if not is_udp_packet(packet):
        return False
    ip = packet.data
    udp = ip.data
    rtp = dpkt.rtp.RTP(udp.data)
    return rtp.version == 2 and (64 <= rtp.pt and rtp.pt < 96)


def as_rtp(packet):
    ip = packet.data
    udp = ip.data
    return dpkt.rtp.RTP(udp.data)


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
        streams,
        packets,
        packet_filter=None,
        unknown='pass',
        excluded='drop',
        malformed='drop',
        streamless='drop',
    ):
    """
    Decrypts SRTP and SRTCP `dpkt.Packet`s.
    """
    if not isinstance(streams, (collections.Sequence)):
        streams = [streams]
    streams = [SRTPStream(s) if isinstance(s, SRTP)  else s for s in streams]

    def match(packet):
        for stream in streams:
            if stream.match(packet):
                return stream

    drop_excluded = excluded == 'drop'
    drop_unknown = unknown == 'drop'
    drop_malformed = malformed == 'drop'
    drop_streamless = streamless == 'drop'
    raise_malformed = malformed == 'raise'

    if packet_filter is None:
        packet_filter = lambda frame: True

    for i, (ts, packet) in enumerate(packets):
        if not packet_filter(packet):
            if drop_excluded:
                logger.debug('dropping excluded packet #%d', i + 1)
                continue
        elif is_srtp_packet(packet):
            stream = match(packet)
            if stream is None:
                if drop_streamless:
                    logger.debug('dropping streamless srtp packet #%d', i + 1)
                    continue
                logger.debug('keeping streamless srtp packet #%d', i + 1)
            else:
                try:
                    packet = stream.decrypt_srtp_packet(packet)
                except SRTPError, ex:
                    if drop_malformed:
                        logger.debug('dropping malformed srtp packet #%d', i + 1, exc_info=ex)
                        continue
                    if raise_malformed:
                        raise
                    logger.debug('keeping malformed srtp packet #%d', i + 1, exc_info=ex)
        elif is_srtcp_packet(packet):
            stream = match(packet)
            if stream is None:
                if drop_streamless:
                    logger.debug('dropping streamless srtcp packet #%d', i + 1)
                    continue
                logger.debug('keeping streamless srtcp packet #%d', i + 1)
            else:
                try:
                    packet = stream.decrypt_srtcp_packet(packet)
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


class SRTPStream(object):
    """
    Used to correlate packets and a SRTP context. Currently matches only on:
    
    - ip.dst
    - udp.dport
    
    """

    def __init__(self, key, address=None, port=None):
        if isinstance(key, SRTP):
            self.ctx = key
        else:
            self.ctx = SRTP(SRTPPolicy(
                ssrc_type=SRTPPolicy.SSRC_ANY_INBOUND,
                key=key,
            ))
        self.ctx.init()
        if address:
            address = struct.pack('>4B', *map(int, address.split('.')))
        self.address = address
        self.port = port

    def match(self, packet):
        ip = packet.data
        udp = ip.data
        return (
            (self.address is None or ip.dst == self.address) and
            (self.port is None or udp.dport == self.port)
        )

    def decrypt_srtp_packet(self, packet):
        return decrypt_srtp_packet(self.ctx, packet)

    def decrypt_srtcp_packet(self, packet):
        return decrypt_srtcp_packet(self.ctx, packet)
