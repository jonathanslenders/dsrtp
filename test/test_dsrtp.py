import dpkt
import pytest

import dsrtp


@pytest.mark.parametrize(
    ('capture, material, expected'), [
        ('av.pcap', 'av_srtp_material.hex', 1729),
    ]
)
def test_decrypt_srtp(fixtures, capture, material, expected):
    with dsrtp.SRTP(fixtures.join(material).read().decode('hex')) as ctx, \
            fixtures.join(capture).open('rb') as fo:
        dec_pkts = dsrtp.decrypt_packets(
            ctx,
            dsrtp.read_packets(fo),
            unknown='drop',
            #malformed='raise',
            decrypt_srtcp=False
        )
        count = 0
        for _, pkt in dec_pkts:
            assert dsrtp.is_srtp_packet(pkt)
            count += 1
        assert count == expected


@pytest.mark.parametrize(
    ('capture, material, expected'), [
        #('av.pcap', 'av_srtcp_material.hex', 0),
    ]
)
def test_decrypt_srtcp(fixtures, capture, material, expected):
    with dsrtp.SRTP(fixtures.join(material).read().decode('hex')) as ctx, \
            fixtures.join(capture).open('rb') as fo:
        dec_pkts = dsrtp.decrypt_packets(
            ctx,
            dsrtp.read_packets(fo),
            unknown='drop',
            malformed='raise',
            decrypt_srtp=False
        )
        count = 0
        for _, pkt in dec_pkts:
            assert dsrtp.is_srtp_packet(pkt)
            count += 1
        assert count == expected


@pytest.mark.parametrize(
    ('packet, expected'), [
        ('srtp_packet.hex', True),
        ('srtcp_packet.hex', False),
    ]
)
def test_is_srtp(fixtures, packet, expected):
    raw = fixtures.join(packet).read().decode('hex')
    eth = dpkt.ethernet.Ethernet(raw)
    assert dsrtp.is_srtp_packet(eth) is expected


@pytest.mark.parametrize(
    ('packet, expected'), [
        ('srtp_packet.hex', False),
        ('srtcp_packet.hex', True),
    ]
)
def test_is_srtcp(fixtures, packet, expected):
    raw = fixtures.join(packet).read().decode('hex')
    eth = dpkt.ethernet.Ethernet(raw)
    assert dsrtp.is_srtcp_packet(eth) is expected


@pytest.mark.parametrize(
    ('capture, material, expected'), [
        ('av.pcap', 'av_srtp_material.hex', 1729),
    ]
)
def test_decrypt_to_capture(tmpdir, fixtures, capture, material, expected):
    decrypted_cap = tmpdir.join('decrypted.pcap')

    with dsrtp.SRTP(fixtures.join(material).read().decode('hex')) as ctx, \
            fixtures.join(capture).open('rb') as fo, \
            decrypted_cap.open('wb') as tfo:
        dec_pkts = dsrtp.decrypt_packets(
            ctx,
            dsrtp.read_packets(fo),
            unknown='drop',
        )
        dsrtp.write_packets(tfo, dec_pkts)

    count = 0
    with decrypted_cap.open('rb') as tfo:
        for _ in dsrtp.read_packets(tfo):
            count += 1
    assert count == expected
