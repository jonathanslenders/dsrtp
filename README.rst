=====
dsrtp
=====

.. image:: https://travis-ci.org/mayfieldrobotics/dsrtp.svg
   :target: https://travis-ci.org/mayfieldrobotics/dsrtp
    
.. image:: https://img.shields.io/pypi/v/dsrtp.svg
   :target: https://pypi.python.org/pypi/dsrtp

Simple front-end for decrypting captured `SRTP and SRTCP <https://www.ietf.org/rfc/rfc3711.txt>`_ packets using:

- `libsrtp <https://github.com/cisco/libsrtp>`_ and 
- `dpkt <https://github.com/kbandla/dpkt>`_

install
-------

Install devel `libpcap <https://github.com/the-tcpdump-group/libpcap>`_ and `libsrtp <https://github.com/cisco/libsrtp>`_ if you need to, e.g.:

.. code:: bash

   sudo apt-get install libpcap-dev libsrtp0-dev
   
and then:

.. code:: bash

   pip install dsrtp

usage
-----

command
~~~~~~~

To e.g. decrypt captured packets and write then back to a capture file:

.. code:: bash

   dsrtp test/fixtures/av.pcap /tmp/rtp.pcap -ld -k test/fixtures/av_material.hex

If you have a cluttered capture (e.g. multiple SRTP streams) then you can
select e.g. the in-bound stream by ``address:port`` like:

.. code:: bash

   dsrtp test/fixtures/av.pcap /tmp/rtp.pcap -k test/fixtures/av_material.hex -l d -i 192.168.121.234:60401

lib
~~~

To do the same in code:

.. code:: python

   import dsrtp
   
   enc_km = open('test/fixtures/av_material.hex').read()
   km = dsrtp.KeyingMaterial.unpack_hex(enc_km)
   p = dsrtp.SRTPPolicy(ssrc_type=dsrtp.SRTPPolicy.SSRC_ANY_INBOUND, key=km.local)
   
   with dsrtp.SRTP(p) as ctx, \
           open('test/fixtures/av.pcap', 'rb') as srtp_pcap, \
           open('/tmp/rtp.pcap', 'wb') as rtp_pcap:
     pkts = dsrtp.read_packets(srtp_pcap)
     decrypted_pkts = dsrtp.decrypt_packets(ctx, pkts)
     dsrtp.write_packets(rtp_pcap, decrypted_pkts)

dev
---

Create a `venv <https://virtualenv.pypa.io/en/latest/>`_:

.. code:: bash

   mkvirtualenv dsrtp
   pip install Cython

then get it:

.. code:: bash

   git clone git@github.com:mayfieldrobotics/dsrtp.git
   cd dsrtp
   workon dsrtp
   pip install -e .[test]

and test it:

.. code:: bash

   py.test test/ --cov dsrtp --cov-report term-missing --pep8

release
-------

Tests pass:

.. code:: bash

   py.test test/ --cov dsrtp --cov-report term-missing --pep8

so update ``__version__`` in:

- ``dsrtp/__init__.py``

commit and tag it:

.. code:: bash

   git commit -am "release v{version}"
   git tag -a v{version} -m "release v{version}"
   git push --tags

and `travis <https://travis-ci.org/mayfieldrobotics/dsrtp>`_ will publish it to `pypi <https://pypi.python.org/pypi/dsrtp/>`_.
