virtual std::optional<bool> OpX509_STORE_CTX_Verify(operation::X509_STORE_CTX_Verify& op) {
    std::optional<bool> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
    
    X509_STORE *store = nullptr;
    STACK_OF(X509) *chain = nullptr;
    X509_STORE_CTX *store_ctx = nullptr;
    const uint8_t *ntlsa_data = reinterpret_cast<const uint8_t*>(op.ntlsa[0].GetData());
    const uint8_t *ncert_data = reinterpret_cast<const uint8_t*>(op.ncert[0].GetData());

    // Initialize the X509 store
    {
        CF_CHECK_NE(store = X509_STORE_new(), nullptr);

        // Add trust anchor certificates
        for (const auto& cert_comp : op.ntlsa) {
            X509 *cert = nullptr;
            const unsigned char *p = cert_comp.GetData();

            CF_CHECK_NE(cert = d2i_X509(nullptr, &p, cert_comp.GetSize()), nullptr);
            CF_CHECK_EQ(X509_STORE_add_cert(store, cert), 1);
            X509_free(cert);
        }
    }

    // Create certificate chain for verification
    {
        CF_CHECK_NE(chain = sk_X509_new_null(), nullptr);
        
        // Add non-trusted certificates
        for (const auto& cert_comp : op.ncert) {
            X509 *cert = nullptr;
            const unsigned char *p = cert_comp.GetData();
            
            CF_CHECK_NE(cert = d2i_X509(nullptr, &p, cert_comp.GetSize()), nullptr);
            sk_X509_push(chain, cert);
        }
    }

    // Initialize the store context
    {
        CF_CHECK_NE(store_ctx = X509_STORE_CTX_new(), nullptr);
        CF_CHECK_EQ(X509_STORE_CTX_init(store_ctx, store, nullptr, chain), 1);

        // Set verification flags
        X509_VERIFY_PARAM *param = X509_STORE_CTX_get0_param(store_ctx);
        if (param) {
            X509_VERIFY_PARAM_set_flags(param, op.noncheck.GetValue());
        }

        // Perform the verification
        int result = X509_STORE_CTX_verify(store_ctx);
        CF_CHECK_NE(result, -1);

        ret = (result == 1);
    }

end:
    X509_STORE_CTX_free(store_ctx);
    sk_X509_pop_free(chain, X509_free);
    X509_STORE_free(store);

    return ret;
}
