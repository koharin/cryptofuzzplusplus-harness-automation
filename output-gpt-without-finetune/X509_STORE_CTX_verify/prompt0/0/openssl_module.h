#if defined(CRYPTOFUZZ_OPENSSL) && !defined(CRYPTOFUZZ_LIBRESSL)
    std::optional<component::VerificationResult> OpX509_STORE_CTX_verify(operation::X509_STORE_CTX_verify& op) {
        size_t ntlsa_size = op.ntlsa.size();
        size_t ncert_size = op.ncert.size();
        
        if (ntlsa_size == 0 || ncert_size == 0) {
            return std::nullopt;
        }
        
        X509_STORE* store = X509_STORE_new();
        if (!store) {
            return std::nullopt;
        }
        
        Datasource ds(op.ntlsa_data.data(), op.ntlsa_data.size());
        
        const uint8_t* ntlsa_data = op.ntlsa_data.data();
        const unsigned char* p = ntlsa_data;
        
        X509* cert = d2i_X509(NULL, &p, ntlsa_size);
        if (cert) {
            X509_STORE_add_cert(store, cert);
            X509_free(cert);
        }
        
        STACK_OF(X509)* chain = sk_X509_new_null();
        if (!chain) {
            X509_STORE_free(store);
            return std::nullopt;
        }
        
        const uint8_t* ncert_data = op.ncert.data();
        p = ncert_data;
        cert = d2i_X509(NULL, &p, ncert_size);
        if (cert) {
            sk_X509_push(chain, cert);
        } else {
            sk_X509_pop_free(chain, X509_free);
            X509_STORE_free(store);
            return std::nullopt;
        }
        
        X509_STORE_CTX* store_ctx = X509_STORE_CTX_new();
        if (!store_ctx) {
            sk_X509_pop_free(chain, X509_free);
            X509_STORE_free(store);
            return std::nullopt;
        }
        
        if (X509_STORE_CTX_init(store_ctx, store, NULL, chain) != 1) {
            X509_STORE_CTX_free(store_ctx);
            sk_X509_pop_free(chain, X509_free);
            X509_STORE_free(store);
            return std::nullopt;
        }
        
        long verify_flags = X509_V_FLAG_DEFAULT;
        const uint8_t* noncheck_data = op.noncheck.data();
        size_t noncheck_size = op.noncheck.size();
        if (noncheck_size > 0) {
            verify_flags |= noncheck_data[0] & 0xFF;
        }
        
        X509_VERIFY_PARAM* param = X509_STORE_CTX_get0_param(store_ctx);
        if (param) {
            X509_VERIFY_PARAM_set_flags(param, verify_flags);
        }
        
        int ret = X509_STORE_CTX_verify(store_ctx);
        
        X509_STORE_CTX_free(store_ctx);
        sk_X509_pop_free(chain, X509_free);
        X509_STORE_free(store);
        
        if (ret == 1) {
            return component::VerificationResult::VALID;
        } else if (ret == 0) {
            return component::VerificationResult::INVALID;
        } else {
            return std::nullopt;
        }
    }
#endif
