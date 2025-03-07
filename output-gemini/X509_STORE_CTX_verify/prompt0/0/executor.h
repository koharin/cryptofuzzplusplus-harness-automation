/* Type aliases */
using ExecutorX509_STORE_CTX_verify = ExecutorBase<bool, operation::X509_STORE_CTX_verify, X509_STORE_CTX_verify_Pair>;

/* Pool declaration */
extern MutatorPool<X509_STORE_CTX_verify_Pair, cryptofuzz::config::kMutatorPoolSize> Pool_X509_STORE_CTX_verify;

/* Operation implementation */
std::optional<bool> OpenSSL::OpX509_STORE_CTX_verify(operation::X509_STORE_CTX_verify& op) {
    auto& ntlsa = op.param.ntlsa;
    auto& ncert = op.param.ncert;
    auto& noncheck = op.param.noncheck;

    /* Create a new OpenSSL X509_STORE object for the trusted certificates. */
    X509_STORE *store = X509_STORE_new();
    if (!store) {
        return std::nullopt;
    }

    /* Add the trusted certificates to the store. */
    const unsigned char *ntlsa_data = ntlsa.data();
    X509 *cert = d2i_X509(NULL, &ntlsa_data, ntlsa.size());
    if (cert) {
        X509_STORE_add_cert(store, cert);
        X509_free(cert);
    }

    /* Create a new OpenSSL STACK_OF(X509) object for the certificate chain. */
    STACK_OF(X509) *chain = sk_X509_new_null();
    if (!chain) {
        X509_STORE_free(store);
        return std::nullopt;
    }

    /* Add the certificate to be verified to the chain. */
    const unsigned char *ncert_data = ncert.data();
    cert = d2i_X509(NULL, &ncert_data, ncert.size());
    if (cert) {
        sk_X509_push(chain, cert);
    } else {
        sk_X509_pop_free(chain, X509_free);
        X509_STORE_free(store);
        return std::nullopt;
    }

    /* Create a new OpenSSL X509_STORE_CTX object. */
    X509_STORE_CTX *store_ctx = X509_STORE_CTX_new();
    if (!store_ctx) {
        sk_X509_pop_free(chain, X509_free);
        X509_STORE_free(store);
        return std::nullopt;
    }

    /* Initialize the X509_STORE_CTX object. */
    if (X509_STORE_CTX_init(store_ctx, store, NULL, chain) != 1) {
        X509_STORE_CTX_free(store_ctx);
        sk_X509_pop_free(chain, X509_free);
        X509_STORE_free(store);
        return std::nullopt;
    }

    /* Set the verification flags. */
    long verify_flags = X509_V_FLAG_DEFAULT;
    if (noncheck.size() > 0) {
        verify_flags |= noncheck[0] & 0xFF;
    }
    X509_VERIFY_PARAM *param = X509_STORE_CTX_get0_param(store_ctx);
    if (param) {
        X509_VERIFY_PARAM_set_flags(param, verify_flags);
    }

    /* Verify the certificate chain. */
    int ret = X509_STORE_CTX_verify(store_ctx);

    /* Free the OpenSSL objects. */
    X509_STORE_CTX_free(store_ctx);
    sk_X509_pop_free(chain, X509_free);
    X509_STORE_free(store);

    return (ret == 1);
}
