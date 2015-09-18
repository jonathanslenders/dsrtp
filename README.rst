=====
dsrtp
=====

Simple front-end for decrypting captured `SRTP <>`_ and `SRTCP <>`_ packets using:

- `libsrtp <>`_ and 
- `dpkt <>`_

install
-------

.. code:: bash

   pip install dsrtp

dev
---

Create a `venv <>`_:

.. code:: bash

   mkvirtualenv dsrtp
   pip install Cython

then install devel `libsrtp <>`_ if you need to, e.g.:

.. code:: bash

   sudo apt-get install libsrtp0-dev

and then get it:

.. code:: bash

   git clone git@github.com:mayfieldrobotics/dsrtp.git
   cd dsrtp
   workon dsrtp
   pip install -e .[test]

and test it:

.. code:: bash

   py.test test/ --cov dsrtp --cov-report term-missing --pep8

usage
-----

code
~~~~

To e.g. decrypt captured packets and write then back to a capture file:

.. code:: python

   import dsrtp
    
   material = 'hex-encoding-of-dtls-keying-material'.decode('hex') 
    
   with dsrtp.SRTP(material) as ctx, \
            open('/path/to/srtp.pcap', 'rb') as srtp_pcap, \
            open('/path/to/rtp.pcap', 'rb') as rtp_pcap:
      pkts = dsrtp.read_packets(srtp_pcap)
      decrypted_pkts = decrypt_srtp_packet(ctx, pkts)
      dsrtp.write_packets(decrypted_pkts)

cli
~~~

To do the same as a command:

.. code:: bash

   dsrtp /path/to/srtp.pcap /path/to/rtp.pcap

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
