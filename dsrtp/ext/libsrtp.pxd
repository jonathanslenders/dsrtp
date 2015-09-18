cdef extern from 'srtp/err.h':

    enum err_status_t:
    
        err_status_ok
        err_status_fail
        err_status_bad_param
        err_status_alloc_fail
        err_status_dealloc_fail
        err_status_init_fail
        err_status_terminus
        err_status_auth_fail
        err_status_cipher_fail
        err_status_replay_fail
        err_status_replay_old
        err_status_algo_fail
        err_status_no_such_op
        err_status_no_ctx
        err_status_cant_check
        err_status_key_expired
        err_status_socket_err
        err_status_signal_err
        err_status_nonce_bad
        err_status_read_fail
        err_status_write_fail
        err_status_parse_err
        err_status_encode_err
        err_status_semaphore_err
        err_status_pfkey_err


cdef extern from 'srtp/srtp.h':
    
    struct crypto_policy_t:
    
        pass
    
    enum ssrc_type_t:
    
        ssrc_undefined
        ssrc_specific
        ssrc_any_inbound
        ssrc_any_outbound
        
    struct ssrc_t:
    
        int type
        unsigned int value

    struct srtp_ctx_t:
    
        pass
    
    struct srtp_policy_t:
    
        ssrc_t ssrc
        crypto_policy_t rtp
        crypto_policy_t rtcp
        unsigned char *key
        unsigned long window_size
        int allow_repeat_tx
        srtp_policy_t *next

    ctypedef srtp_ctx_t *srtp_t

    err_status_t srtp_init()
    
    err_status_t srtp_shutdown()
    
    err_status_t srtp_protect(srtp_t ctx, void *rtp_hdr, int *len_ptr)
    
    err_status_t srtp_unprotect(srtp_t ctx, void *srtp_hdr, int *len_ptr)

    err_status_t srtp_create(srtp_t *session, const srtp_policy_t *policy)

    void crypto_policy_set_rtp_default(crypto_policy_t *p)
    
    void crypto_policy_set_rtcp_default(crypto_policy_t *p)
    
    err_status_t srtp_dealloc(srtp_t s)

    err_status_t srtp_protect_rtcp(srtp_t ctx, void *rtcp_hdr, int *pkt_octet_len)
    
    err_status_t srtp_unprotect_rtcp(srtp_t ctx, void *srtcp_hdr, int *pkt_octet_len)
