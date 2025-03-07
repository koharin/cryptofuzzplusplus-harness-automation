/* Specialization for operation::X509_STORE_CTX_Verify */
template<> void ExecutorBase<bool, X509_Store_CTX_Verify>::postprocess(std::shared_ptr<Module> module, X509_Store_CTX_Verify& op, const ExecutorBase<bool, X509_Store_CTX_Verify>::ResultPair& result) const {
    (void)module;
    (void)op;
    (void)result;
}

template<> std::optional<bool> ExecutorBase<bool, X509_Store_CTX_Verify>::callModule(std::shared_ptr<Module> module, X509_Store_CTX_Verify& op) const {
    X509_STORE* store = X509_STORE_new();
    if (!store) {
        return std::nullopt;
    }
    
    const unsigned char* p = op.ntlsa_data.GetPtr();
    X509* cert = d2i_X509(NULL, &p, op.ntlsa_data.GetSize());
    if (cert) {
        X509_STORE_add_cert(store, cert);
        X509_free(cert);
    } else {
        X509_STORE_free(store);
        return std::nullopt;
    }

    STACK_OF(X509)* chain = sk_X509_new_null();
    if (!chain) {
        X509_STORE_free(store);
        return std::nullopt;
    }

    p = op.ncert.GetPtr();
    cert = d2i_X509(NULL, &p, op.ncert.GetSize());
    if (cert) {
        sk_X509_push(chain, cert);
    } else {
        sk_X509_free(chain, X509_free);
        X509_STORE_free(store);
        return std::nullopt;
    }

    long verify_flags = X509_V_FLAG_DEFAULT;
    if (op.noncheck.GetSize() > 0) {
        verify_flags |= op.noncheck[0] & 0xFF;
    }

    X509_STORE_CTX* store_ctx = X509_STORE_CTX_new();
    if (!store_ctx) {
        sk_X509_free(chain, X509_free);
        X509_STORE_free(store);
        return std::nullopt;
    }

    if (X509_STORE_CTX_init(store_ctx, store, NULL, chain) != 1) {
        X509_STORE_CTX_free(store_ctx);
        sk_X509_free(chain, X509_free);
        X509_STORE_free(store);
        return std::nullopt;
    }

    X509_VERIFY_PARAM* param = X509_STORE_CTX_get0_param(store_ctx);
    if (param) {
        X509_VERIFY_PARAM_set_flags(param, verify_flags);
    }

    int ret = X509_STORE_CTX_verify(store_ctx);

    X509_STORE_CTX_free(store_ctx);
    sk_X509_free(chain, X509_free);
    X509_STORE_free(store);

    return ret == 1;
}

/* Explicit template instantiation */
template class ExecutorBase<bool, X509_Store_CTX_Verify>;
