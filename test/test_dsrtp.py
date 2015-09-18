import dpkt
import pytest

import dsrtp


@pytest.mark.parametrize(
    'material', [
        'av_material.hex',
    ]
)
def test_keying_material(fixtures, material):
    encoded = fixtures.join(material).read()
    km = dsrtp.KeyingMaterial.unpack_encoded(encoded)

    assert len(km.local_secret) == dsrtp.KeyingMaterial.SECRET_LEN
    assert len(km.local_salt) == dsrtp.KeyingMaterial.SALT_LEN
    assert len(km.local) == dsrtp.KeyingMaterial.LEN

    assert len(km.remote_secret) == dsrtp.KeyingMaterial.SECRET_LEN
    assert len(km.remote_salt) == dsrtp.KeyingMaterial.SALT_LEN
    assert len(km.remote) == dsrtp.KeyingMaterial.LEN

    assert km.pack().encode('hex') == encoded


@pytest.mark.parametrize(
    'material', [
        'av_material.hex',
    ]
)
def test_srtp_policies(fixtures, material):
    encoded = fixtures.join(material).read()
    km = dsrtp.KeyingMaterial.unpack_encoded(encoded)

    ps = dsrtp.SRTPPolicies()

    p1 = dsrtp.SRTPPolicy(
        ssrc_type=dsrtp.SRTPPolicy.SSRC_ANY_INBOUND,
        key=km.local,
    )

    p2 = dsrtp.SRTPPolicy(
        ssrc_type=dsrtp.SRTPPolicy.SSRC_ANY_OUTBOUND,
        key=km.remote,
    )

    assert len(ps) == 0
    assert p1.next is None
    assert p2.next is None

    ps.append(p1)
    assert len(ps) == 1
    assert p1.next is None
    assert p2.next is None

    ps.append(p2)
    assert len(ps) == 2
    assert p1.next is p2
    assert p2.next is None

    del ps[0]
    assert len(ps) == 1
    assert p1.next is None
    assert p2.next is None

    ps.append(p1)
    assert p2.next is p1
    assert p1.next is None


@pytest.mark.parametrize(
    ('capture, material, in_address, in_port, expected'), [
        ('av.pcap', 'av_material.hex', '192.168.121.234', 60401, 1759),
    ]
)
def test_decrypt_inbound_srtp(
        fixtures,
        capture,
        material,
        in_address,
        in_port,
        expected):
    km = dsrtp.KeyingMaterial.unpack_encoded(
        fixtures.join(material).read()
    )
    with fixtures.join(capture).open('rb') as fo:
        dec_pkts = dsrtp.decrypt_packets(
            dsrtp.SRTPStream(km.remote, in_address, in_port),
            dsrtp.read_packets(fo),
            unknown='drop',
            malformed='raise',
        )
        count = 0
        for _, pkt in dec_pkts:
            assert (
                dsrtp.is_srtp_packet(pkt) or dsrtp.is_srtcp_packet(pkt)
            )
            count += 1
        assert count == expected


@pytest.mark.parametrize(
    ('capture, material, out_address, out_port, expected'), [
        ('av.pcap', 'av_material.hex', '192.168.121.234', 49686, 15),
    ]
)
def test_decrypt_outbound_srtp(
        fixtures,
        capture,
        material,
        out_address,
        out_port,
        expected):
    km = dsrtp.KeyingMaterial.unpack_encoded(
        fixtures.join(material).read()
    )
    with fixtures.join(capture).open('rb') as fo:
        dec_pkts = dsrtp.decrypt_packets(
            dsrtp.SRTPStream(km.local, out_address, out_port),
            dsrtp.read_packets(fo),
            unknown='drop',
            malformed='raise',
        )
        count = 0
        for _, pkt in dec_pkts:
            assert (
                dsrtp.is_srtp_packet(pkt) or dsrtp.is_srtcp_packet(pkt)
            )
            count += 1
        assert count == expected


@pytest.mark.parametrize(
    ('capture, material, expected'), [
        ('av.pcap', 'av_material.hex', 1759 + 15),
    ]
)
def test_inbound_and_outbound(tmpdir, fixtures, capture, material, expected):
    km = dsrtp.KeyingMaterial.unpack_encoded(
        fixtures.join(material).read()
    )
    decrypted_cap = tmpdir.join('decrypted.pcap')

    streams = [
        dsrtp.SRTPStream(km.remote, '192.168.121.234', 60401),
        dsrtp.SRTPStream(km.local, '192.168.121.234', 49686),
    ]

    with fixtures.join(capture).open('rb') as fo, \
            decrypted_cap.open('wb') as tfo:
        dec_pkts = dsrtp.decrypt_packets(
            streams,
            dsrtp.read_packets(fo),
            unknown='drop',
            malformed='raise',
        )
        dsrtp.write_packets(tfo, dec_pkts)

    count = 0
    with decrypted_cap.open('rb') as tfo:
        for _ in dsrtp.read_packets(tfo):
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
