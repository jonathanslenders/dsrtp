import collections
import logging
import StringIO

cimport cpython
cimport libc.string
cimport libsrtp


logger = logging.getLogger('dsrtp.ext')


DEF SRTP_MASTER_KEY_SECRET_LEN = 16

DEF SRTP_MASTER_KEY_SALT_LEN = 14

DEF SRTP_MASTER_KEY_LEN = (SRTP_MASTER_KEY_SECRET_LEN + SRTP_MASTER_KEY_SALT_LEN)


class KeyingMaterial(object):
    """
    DTLS negotiated keying material (i.e. secret and salt) which should be used
    as policy keys.
    """
    
    SECRET_LEN = SRTP_MASTER_KEY_SECRET_LEN
    
    SALT_LEN = SRTP_MASTER_KEY_SALT_LEN
    
    LEN = SRTP_MASTER_KEY_LEN

    def __init__(self, local_secret, local_salt, remote_secret, remote_salt):
        self.local_secret = local_secret
        self.local_salt = local_salt
        self.remote_secret = remote_secret
        self.remote_salt = remote_salt
        
    @property
    def local(self):
        return self.local_secret + self.local_salt
    
    @property
    def remote(self):
        return self.remote_secret + self.remote_salt

    @classmethod
    def unpack(cls, io):
        if isinstance(io, basestring):
            io = StringIO.StringIO(io)
        local_secret = io.read(cls.SECRET_LEN)
        remote_secret = io.read(cls.SECRET_LEN)
        local_salt = io.read(cls.SALT_LEN)
        remote_salt = io.read(cls.SALT_LEN)
        if (len(local_secret) != cls.SECRET_LEN or
            len(remote_secret) != cls.SECRET_LEN or
            len(local_salt) != cls.SALT_LEN or
            len(remote_salt) != cls.SALT_LEN):
            raise ValueError(
                'Packed keying material must have length {0}'
                .format(cls.LEN * 2)
            )
        return cls(
            local_secret=local_secret,
            remote_secret=remote_secret,
            local_salt=local_salt,
            remote_salt=remote_salt,
        )

    @classmethod
    def unpack_encoded(cls, encoding):
        try:
            return cls.unpack_hex(encoding)
        except TypeError, ex:
            if 'Non-hexadecimal digit found' not in str(ex):
                raise
            return cls.unpack_b64(encoding)

    @classmethod
    def unpack_hex(cls, encoding):
        return cls.unpack(encoding.decode('hex'))

    @classmethod
    def unpack_b64(cls, encoding):
        return cls.unpack(encoding.decode('base64'))

    def pack(self):
        return (
            self.local_secret +
            self.remote_secret +
            self.local_salt +
            self.remote_salt
        )


cdef class SRTPPolicy(object):
    """
    Wrapper for libsrtp.srtp_policy_t. Add these to SRTPPolicies which manages
    libsrtp.srtp_policy_t.next.
    """
    
    SSRC_UNDEFINED = <int>libsrtp.ssrc_undefined
    SSRC_SPECIFIC = <int>libsrtp.ssrc_specific
    SSRC_ANY_INBOUND = <int>libsrtp.ssrc_any_inbound
    SSRC_ANY_OUTBOUND = <int>libsrtp.ssrc_any_outbound

    cdef libsrtp.srtp_policy_t policy
    cdef object _key
    cdef object _next
    
    def __cinit__(self):
        libc.string.memset(&self.policy, 0, sizeof(self.policy))
        libsrtp.crypto_policy_set_rtp_default(&(self.policy.rtp))
        libsrtp.crypto_policy_set_rtcp_default(&(self.policy.rtcp))
        self._key = None
        self._next = None
        
    def __init__(self,
                ssrc_type=None,
                ssrc_value=None,
                key=None,
                window_size=None,
                next=None
            ):
        if ssrc_type is not None:
            self.ssrc_type = ssrc_type
        if ssrc_value is not None:
            self.ssrc_value = ssrc_value
        if window_size is not None:
            self.window_size = window_size
        self.key = key
        self.next = next

    property ssrc_type:
    
        def __get__(self):
            return self.policy.ssrc.type

        def __set__(self, int value):
            if not (self.SSRC_UNDEFINED <= value <= self.SSRC_ANY_OUTBOUND):
                raise ValueError('Invalid ssrc type {0}'.format(value))
            self.policy.ssrc.type = value

    property ssrc_value:
    
        def __get__(self):
            return self.policy.ssrc.value

        def __set__(self, unsigned int value):
            self.policy.ssrc.value = value
    
    property key:
    
        def __get__(self):
            return self.key

        def __set__(self, object value):
            if value is None:
                self.policy.key = NULL
            else:
                if not isinstance(value, basestring):
                    raise TypeError('Policy key must be a string')
                if len(value) != SRTP_MASTER_KEY_LEN:
                    raise ValueError(
                        'Policy key must have length {0} (!= {1})'
                        .format(SRTP_MASTER_KEY_LEN, len(value))
                    )
                self.policy.key = <unsigned char*>cpython.PyString_AsString(value)
            self._key = value
    
    property window_size:
    
        def __get__(self):
            return self.policy.window_size

        def __set__(self, unsigned long value):
            self.policy.window_size = value

    property next:
    
        def __get__(self):
            return self._next

        def __set__(self, SRTPPolicy value):
            if value is None:
                self.policy.next = NULL
            else:
                self.policy.next = &(value.policy)
            self._next = value


class SRTPPolicies(collections.MutableSequence):
    """
    Managed SRTPPolicy collection.
    """
    
    def __init__(self, policies=None):
        self._policies = []
        if policies:
            for policy in policies:
                self.append(policy)
    
    def __getitem__(self, index):
        return self._policies[index]
    
    def __setitem__(self, index, value):
        self._policies[index] = value
        if index != 0:
            self[index - 1].next = value
        if index != len(self) - 1:
            value.next = self[index + 1] 
    
    def __delitem__(self, index):
        if 0 <= index < len(self):
            next = self[index].next
            self[index].next = None
        del self._policies[index]
        if index != 0 and len(self) != 0:
            self[index - 1].next = next
    
    def __len__(self):
        return len(self._policies)
    
    def insert(self, index, value):
        self._policies.insert(index, value)
        if index != 0:
            self[index - 1].next = value
        if index != len(self) - 1:
            value.next = self[index + 1]


cdef class SRTP(object):
    """
    SRTP context.
    """

    cdef object policies
    cdef libsrtp.srtp_t ctx
    
    def __init__(self, policies=None):
        if policies is None:
            self.policies = SRTPPolicies()
        elif isinstance(policies, SRTPPolicy):
            self.policies = SRTPPolicies([policies])
        elif isinstance(policies, SRTPPolicies):
            self.policies = policies
        else:
            raise TypeError('policies= must be SRTPPolicy or SRTPPolicies')

    def __cinit__(self):
        self.ctx = NULL

    def __dealloc__(self):
        self.dealloc()

    cpdef init(self):
        """
        Initializes libsrtp.srtp_t ctx.
        """
        cdef int err
        cdef SRTPPolicy policy_obj
        cdef libsrtp.srtp_policy_t *policy
        cdef unsigned char policy_key[SRTP_MASTER_KEY_LEN]

        # deallocate existing
        self.dealloc()
        
        # get first policy
        if len(self.policies) == 0:
            raise RuntimeError('SRTP.policies must have at least *one* SRTPPolicy')
        policy_obj = self.policies[0]
        policy = &(policy_obj.policy)

        # and create context
        err = libsrtp.srtp_create(&self.ctx, policy)
        if err != libsrtp.err_status_ok:
            raise SRTPError(err)

    cpdef dealloc(self):
        """
        Deallocates initialized libsrtp.srtp_t ctx, or does nothing if it
        hasn't been initialized.
        """
        cdef int err

        if self.ctx != NULL:
            err = libsrtp.srtp_dealloc(self.ctx)
            if err != libsrtp.err_status_ok:
                logger.warning(
                        'failed to deallocate srtp context- %s, %s',
                        SRTPError.errstr(err), err
                    )
            self.ctx = NULL

    cpdef object unprotect(self, object buf):
        """
        Unprotects a SRTP packet using initialized libsrtp.srtp_t ctx. 
        """
        cdef int err
        cdef int data_len
        cdef unsigned char *data
        cdef unsigned char *hdr
        cdef int hdr_len
        cdef object dbuf
        
        if self.ctx == NULL:
            raise RuntimeError('SRTP.init has not been called')

        # copy buffer
        hdr_len = data_len = cpython.PyString_Size(buf)
        hdr = data = <unsigned char *>cpython.PyMem_Malloc(data_len)
        libc.string.memcpy(data, cpython.PyString_AsString(buf), data_len)

        # and un-protect it in-place
        err = libsrtp.srtp_unprotect(self.ctx, hdr, &hdr_len)
        if err == libsrtp.err_status_ok:
            dbuf = cpython.PyString_FromStringAndSize(<char *>hdr, hdr_len)
        if data != NULL:
            cpython.PyMem_Free(data)
            data = NULL

        if err != libsrtp.err_status_ok:
            raise SRTPError(err)

        return dbuf
    
    cpdef object unprotect_control(self, object buf):
        """
        Unprotects a SRTCP packet using initialized libsrtp.srtp_t ctx.
        """
        cdef int err
        cdef int data_len
        cdef unsigned char *data
        cdef unsigned char *hdr
        cdef int hdr_len
        cdef object dbuf
        
        if self.ctx == NULL:
            raise RuntimeError('SRTP.init has not been called')

        # copy buffer
        hdr_len = data_len = cpython.PyString_Size(buf)
        hdr = data = <unsigned char *>cpython.PyMem_Malloc(data_len)
        libc.string.memcpy(data, cpython.PyString_AsString(buf), data_len)

        # and un-protect it in-place
        err = libsrtp.srtp_unprotect_rtcp(self.ctx, hdr, &hdr_len)
        if err == libsrtp.err_status_ok:
            dbuf = cpython.PyString_FromStringAndSize(<char *>hdr, hdr_len)
        if data != NULL:
            cpython.PyMem_Free(data)
            data = NULL

        if err != libsrtp.err_status_ok:
            raise SRTPError(err)

        return dbuf

    def __enter__(self):
        self.init()
        return self

    def __exit__(self, type, value, traceback):
        self.dealloc()


class SRTPError(Exception):
    """
    Exception wrapper for libsrtp.err_status_t.
    """

    def __init__(self, errno):
        super(SRTPError, self).__init__(self.errstr(errno))
        self.errno = errno

    OK = <int>libsrtp.err_status_ok
    FAIL = <int>libsrtp.err_status_fail
    BAD_PARAM = <int>libsrtp.err_status_bad_param
    ALLOC_FAIL = <int>libsrtp.err_status_alloc_fail
    DEALLOC_FAIL = <int>libsrtp.err_status_dealloc_fail
    INIT_FAIL = <int>libsrtp.err_status_init_fail
    TERMINUS = <int>libsrtp.err_status_terminus
    AUTH_FAIL = <int>libsrtp.err_status_auth_fail
    CIPHER_FAIL = <int>libsrtp.err_status_cipher_fail
    REPLAY_FAIL = <int>libsrtp.err_status_replay_fail
    REPLAY_OLD = <int>libsrtp.err_status_replay_old
    ALGO_FAIL = <int>libsrtp.err_status_algo_fail
    NO_SUCH_OP = <int>libsrtp.err_status_no_such_op
    NO_CTX = <int>libsrtp.err_status_no_ctx
    CANT_CHECK = <int>libsrtp.err_status_cant_check
    KEY_EXPIRED = <int>libsrtp.err_status_key_expired
    SOCKET_ERR = <int>libsrtp.err_status_socket_err
    SIGNAL_ERR = <int>libsrtp.err_status_signal_err
    NONCE_BAD = <int>libsrtp.err_status_nonce_bad
    READ_FAIL = <int>libsrtp.err_status_read_fail
    WRITE_FAIL = <int>libsrtp.err_status_write_fail
    PARSE_ERR = <int>libsrtp.err_status_parse_err
    ENCODE_ERR = <int>libsrtp.err_status_encode_err
    SEMAPHORE_ERR = <int>libsrtp.err_status_semaphore_err
    PFKEY_ERR = <int>libsrtp.err_status_pfkey_err

    errstrs = {
        OK: 'Nothing to report',
        FAIL: 'Unspecified failure',
        BAD_PARAM: 'Unsupported parameter',
        ALLOC_FAIL: 'Couldn\'t allocate memory',
        DEALLOC_FAIL: 'Couldn\'t deallocate properly',
        INIT_FAIL: 'Couldn\'t initialize',
        TERMINUS: 'Can\'t process as much data as requested',
        AUTH_FAIL: 'Authentication failure',
        CIPHER_FAIL: 'Cipher failure',
        REPLAY_FAIL: 'Replay check failed (bad index)',
        REPLAY_OLD: 'Replay check failed (index too old)',
        ALGO_FAIL: 'Algorithm failed test routine',
        NO_SUCH_OP: 'Unsupported operation',
        NO_CTX: 'No appropriate context found',
        CANT_CHECK: 'Unable to perform desired validation',
        KEY_EXPIRED: 'Can\'t use key any more',
        SOCKET_ERR: 'Error in use of socket',
        SIGNAL_ERR: 'Error in use POSIX signals',
        NONCE_BAD: 'Nonce check failed',
        READ_FAIL: 'Couldn\'t read data',
        WRITE_FAIL: 'Couldn\'t write data',
        PARSE_ERR: 'Error pasring data',
        ENCODE_ERR: 'Error encoding data',
        SEMAPHORE_ERR: 'Error while using semaphores',
        PFKEY_ERR: 'Error while using pfkey',
    }

    @classmethod
    def errstr(cls, errno):
        return cls.errstrs.get(errno, 'Unknown')


cdef void init():
    """
    Initializes libsrtp. Called automatically when this module is loaded.
    """
    cdef int err
    err = libsrtp.srtp_init()
    if err != libsrtp.err_status_ok:
        raise SRTPError(err)


init()
