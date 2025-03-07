void Driver::Run(const uint8_t* data, const size_t size) const {
    try {
        Datasource ds(data, size);

        // Extract operation ID
        const auto operation = ds.Get<uint64_t>();

        if (!options.operations.Have(operation)) {
            return;
        }

        // Extract payload
        const auto payload = ds.GetData(0, 1);

        switch (operation) {
            case CF_OPERATION("X509_STORE_CTX_Verify"): {
                std::optional<bool> verificationResult = std::nullopt;

                // Define mutation variables
                const auto ntlsa = ds.GetData(0, 1);
                const auto ncert = ds.GetData(0, 1);
                const auto noncheck = ds.GetData(0, 1);
                size_t ntlsa_size = ntlsa.size();
                size_t ncert_size = ncert.size();

                const uint8_t *ntlsa_data = ntlsa.data();
                const uint8_t *ncert_data = ncert.data();
                
                X509_STORE *store = nullptr;
                STACK_OF(X509) *chain = nullptr;
                X509_STORE_CTX *store_ctx = nullptr;

                // Initialize the X509 store
                CF_CHECK_NE(store = X509_STORE_new(), nullptr);
                {
                    for (size_t i = 0; i < ntlsa_size; i += sizeof(cert_component)) {
                        X509 *cert = nullptr;
                        const unsigned char *p = ntlsa_data + i;

                        CF_CHECK_NE(cert = d2i_X509(nullptr, &p, ntlsa_size - i), nullptr);
                        CF_CHECK_EQ(X509_STORE_add_cert(store, cert), 1);
                        X509_free(cert);
                    }
                }

                // Create certificate chain for verification
                CF_CHECK_NE(chain = sk_X509_new_null(), nullptr);
                {
                    for (size_t i = 0; i < ncert_size; i += sizeof(cert_component)) {
                        X509 *cert = nullptr;
                        const unsigned char *p = ncert_data + i;

                        CF_CHECK_NE(cert = d2i_X509(nullptr, &p, ncert_size - i), nullptr);
                        sk_X509_push(chain, cert);
                    }
                }

                // Initialize the store context
                CF_CHECK_NE(store_ctx = X509_STORE_CTX_new(), nullptr);
                CF_CHECK_EQ(X509_STORE_CTX_init(store_ctx, store, nullptr, chain), 1);

                // Set verification flags using noncheck
                X509_VERIFY_PARAM *param = X509_STORE_CTX_get0_param(store_ctx);
                if (param) {
                    X509_VERIFY_PARAM_set_flags(param, noncheck[0] & 0xFF);
                }

                // Perform the verification
                int result = X509_STORE_CTX_verify(store_ctx);
                CF_CHECK_NE(result, -1);

                verificationResult = (result == 1);

                // Cleanup
                X509_STORE_CTX_free(store_ctx);
                sk_X509_pop_free(chain, X509_free);
                X509_STORE_free(store);

                break;
            }
        }
    } catch (Datasource::OutOfData) {
    }
}
