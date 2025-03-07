std::optional<bool> OpenSSL::OpEVP_PKEY_verify(operation::EVP_PKEY_verify& op) {
    std::optional<bool> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    global_ds = &ds;

    EVP_PKEY_CTX* ctx = nullptr;
    EVP_PKEY* pkey = nullptr;
    int result = 0;

    try {
        /* Initialize */
        {
            std::optional<std::vector<uint8_t>> cleartext = nullptr;
            cleartext = op.cleartext.Get();

            /* OpenSSL initialization code for EVP_PKEY_verify */
            CF_CHECK_NE(pkey = EVP_PKEY_new(), nullptr);
            CF_CHECK_NE(ctx = EVP_PKEY_CTX_new(pkey, NULL), nullptr);
            CF_CHECK_EQ(EVP_PKEY_verify_init(ctx), 1);

            /* Suppose that the operation parameters can be adjusted here */
            {
                result = EVP_PKEY_verify(
                    ctx,
                    cleartext->data(),
                    cleartext->size(),
                    cleartext->data(),
                    cleartext->size()
                );
                /* result processing code for EVP_PKEY_verify */
            }
        }

        /* Finalize */
        {
            ret = (result == 1);
        }
    } catch ( ... ) {
        /* Handle exceptions if necessary */
    }

end:
    if (ctx != nullptr) {
        EVP_PKEY_CTX_free(ctx);
    }

    if (pkey != nullptr) {
        EVP_PKEY_free(pkey);
    }

    global_ds = nullptr;

    return ret;
}
