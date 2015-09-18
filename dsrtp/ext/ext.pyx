import logging

cimport cpython
cimport libc.string
cimport libsrtp


logger = logging.getLogger('dsrtp.ext')

DEF SRTP_MASTER_KEY_SECRET_LEN = 16

DEF SRTP_MASTER_KEY_SALT_LEN = 14

DEF SRTP_MASTER_KEY_LEN = (SRTP_MASTER_KEY_SECRET_LEN + SRTP_MASTER_KEY_SALT_LEN)


cdef class SRTP(object):
    """
    """

    cdef object keying_material
    cdef libsrtp.srtp_t ctx
    cdef unsigned char * local_secret
    cdef unsigned char * local_salt
    cdef unsigned char * remote_secret
    cdef unsigned char * remote_salt

    def __cinit__(self, object keying_material):
        cdef unsigned char * buf
        
        # validate keying material
        if not isinstance(keying_material, str):
            raise TypeError(
                    'keying_material must be a {0} length byte string'
                    .format(SRTP_MASTER_KEY_LEN)
                )
        if len(keying_material) != SRTP_MASTER_KEY_LEN * 2:
            raise ValueError(
                    'Invalid keying_material length {0} (!={1})'
                    .format(len(keying_material), SRTP_MASTER_KEY_LEN * 2)
                )
        self.keying_material = keying_material

        # local/remote key and salt in keying material
        buf = < unsigned char *> cpython.PyString_AsString(self.keying_material)
        self.local_secret = buf
        self.remote_secret = self.local_secret + SRTP_MASTER_KEY_SECRET_LEN
        self.local_salt = self.remote_secret + SRTP_MASTER_KEY_SECRET_LEN
        self.remote_salt = self.local_salt + SRTP_MASTER_KEY_SALT_LEN

        # context
        self.ctx = NULL

    def __dealloc__(self):
        self.dealloc()

    cpdef init(self):
        """
        """
        cdef int err
        cdef libsrtp.srtp_policy_t policy
        cdef unsigned char policy_key[SRTP_MASTER_KEY_LEN];

        # deallocate existing
        self.dealloc()

        # setup policy
        libc.string.memset(& policy, 0, sizeof(policy))
        libsrtp.crypto_policy_set_rtp_default(& (policy.rtp))
        libsrtp.crypto_policy_set_rtcp_default(& (policy.rtcp))
        policy.ssrc.type = libsrtp.ssrc_any_inbound
        policy.key = <unsigned char *>&policy_key
        libc.string.memcpy(policy.key, self.remote_secret, SRTP_MASTER_KEY_SECRET_LEN)
        libc.string.memcpy(policy.key + SRTP_MASTER_KEY_SECRET_LEN, self.remote_salt, SRTP_MASTER_KEY_SALT_LEN);
        policy.next = NULL

        # create context
        err = libsrtp.srtp_create(& self.ctx, & policy)
        if err != libsrtp.err_status_ok:
            raise SRTPError(err)

    cpdef dealloc(self):
        """
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
    cdef int err
    err = libsrtp.srtp_init()
    if err != libsrtp.err_status_ok:
        raise SRTPError(err)

init()
