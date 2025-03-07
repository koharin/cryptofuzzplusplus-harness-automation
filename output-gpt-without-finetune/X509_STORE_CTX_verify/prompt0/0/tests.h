#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <optional>

void test(const operation::X509_STORE_CTX_verify& op, const std::optional<bool>& result) {
    // Split input data into three parts: ntlsa, ncert, noncheck
    size_t part_size = op.mutation_data.size() / 3;
    size_t ntlsa_size = part_size;
    size_t ncert_size = part_size;
    size_t noncheck_size = op.mutation_data.size() - 2 * part_size;

    const uint8_t *ntlsa_data = op.mutation_data.data();
    const uint8_t *ncert_data = ntlsa_data + ntlsa_size;
    const uint8_t *noncheck_data = ncert_data + ncert_size;

    // Initialize X509_STORE
    X509_STORE* store = X509_STORE_new();
    if (!store) {
        return;
    }

    // Add certificate to X509_STORE from ntlsa_data
    const unsigned char* p = ntlsa_data;
    X509* cert = d2i_X509(NULL, &p, ntlsa_size);
    if (cert) {
        X509_STORE_add_cert(store, cert);
        X509_free(cert);
    }

    // Create chain stack from ncert_data
    STACK_OF(X509)* chain = sk_X509_new_null();
    if (!chain) {
        X509_STORE_free(store);
        return;
    }

    p = ncert_data;
    cert = d2i_X509(NULL, &p, ncert_size);
    if (cert) {
        sk_X509_push(chain, cert);
    } else {
        sk_X509_pop_free(chain, X509_free);
        X509_STORE_free(store);
        return;
    }

    // Initialize X509_STORE_CTX and set verification flags
    X509_STORE_CTX* store_ctx = X509_STORE_CTX_new();
    if (!store_ctx) {
        sk_X509_pop_free(chain, X509_free);
        X509_STORE_free(store);
        return;
    }

    if (X509_STORE_CTX_init(store_ctx, store, NULL, chain) != 1) {
        X509_STORE_CTX_free(store_ctx);
        sk_X509_pop_free(chain, X509_free);
        X509_STORE_free(store);
        return;
    }

    long verify_flags = X509_V_FLAG_DEFAULT;
    if (noncheck_size > 0) {
        verify_flags |= noncheck_data[0] & 0xFF;
    }

    X509_VERIFY_PARAM* param = X509_STORE_CTX_get0_param(store_ctx);
    if (param) {
        X509_VERIFY_PARAM_set_flags(param, verify_flags);
    }

    // Call X509_STORE_CTX_verify
    int ret = X509_STORE_CTX_verify(store_ctx);

    // Free allocated resources
    X509_STORE_CTX_free(store_ctx);
    sk_X509_pop_free(chain, X509_free);
    X509_STORE_free(store);

    // Store the result if needed
    if (result.has_value()) {
        *const_cast<std::optional<bool>*>(&result) = (ret == 1);
    }
}
