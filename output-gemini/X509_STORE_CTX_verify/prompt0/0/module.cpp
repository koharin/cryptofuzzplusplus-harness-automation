std::optional<bool> OpenSSL::OpX509_STORE_CTX_verify(operation::X509_STORE_CTX_Verify& op) {
    std::optional<bool> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    X509_STORE *store = X509_STORE_new();
    if (!store) {
        return ret;
    }

    STACK_OF(X509) *chain = sk_X509_new_null();
    if (!chain) {
        X509_STORE_free(store);
        return ret;
    }

    /* ntlsa */
    {
        const unsigned char* ntlsa_data = op.ntlsa.GetPtr();
        X509 *cert = d2i_X509(NULL, &ntlsa_data, op.ntlsa.GetSize());
        if (cert) {
            X509_STORE_add_cert(store, cert);
            X509_free(cert);
        }
    }

    /* ncert */
    {
        const unsigned char *p = op.ncert.GetPtr();
        X509 *cert = d2i_X509(NULL, &p, op.ncert.GetSize());
        if (cert) {
            sk_X509_push(chain, cert);
        } else {
            sk_X509_pop_free(chain, X509_free);
            X509_STORE_free(store);
            return ret;
        }
    }

    /* noncheck */
    long verify_flags = X509_V_FLAG_DEFAULT;
    if (op.noncheck.GetSize() > 0) {
        verify_flags |= op.noncheck.Get<uint8_t>(0) & 0xFF;
    }

    X509_STORE_CTX *store_ctx = X509_STORE_CTX_new();
    if (!store_ctx) {
        sk_X509_pop_free(chain, X509_free);
        X509_STORE_free(store);
        return ret;
    }

    if (X509_STORE_CTX_init(store_ctx, store, NULL, chain) != 1) {
        X509_STORE_CTX_free(store_ctx);
        sk_X509_pop_free(chain, X509_free);
        X509_STORE_free(store);
        return ret;
    }

    {
        X509_VERIFY_PARAM *param = X509_STORE_CTX_get0_param(store_ctx);
        if (param) {
            X509_VERIFY_PARAM_set_flags(param, verify_flags);
        }
    }

    int r = X509_STORE_CTX_verify(store_ctx);
    if ( r == 1 ) {
        ret = true;
    } else if ( r == 0 ) {
        ret = false;
    } else {
        /* X509_STORE_CTX_verify failed -- don't set ret */
    }

    X509_STORE_CTX_free(store_ctx);
    sk_X509_pop_free(chain, X509_free);
    X509_STORE_free(store);

    return ret;
}
