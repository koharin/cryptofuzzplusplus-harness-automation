std::optional<bool> OpenSSL::OpEVP_PKEY_Verify(operation::EVP_PKEY_Verify& op) {
    std::optional<bool> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    util::Multipart parts;

    const EVP_MD* md = nullptr;
    EVP_PKEY *pkey = nullptr;

    /* Initialize */
    {
        parts = util::ToParts(ds, op.cleartext);

        CF_CHECK_NE(md = toEVPMD(op.digestType), nullptr);
        CF_CHECK_NE(pkey = getPublicKey(op.keySize), nullptr);

        EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);
        if (!ctx) {
            return ret;
        }
        if (EVP_PKEY_verify_init(ctx) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            return ret;
        }
        if (EVP_PKEY_CTX_set_signature_md(ctx, md) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            return ret;
        }

        /* Process */
        for (const auto& part : parts) {
            /* Assuming EVP_PKEY_verify_update exists and is needed */
            // CF_CHECK_EQ(EVP_PKEY_verify_update(ctx, part.first, part.second), 1);
        }

        /* Finalize */
        int result = EVP_PKEY_verify(ctx, op.signature.GetPtr(), op.signature.GetSize(),
                                      op.cleartext.GetPtr(), op.cleartext.GetSize());
        if (result == 1) {
            ret = true;
        } else if (result == 0) {
            ret = false;
        } // else: error, leave ret as nullopt

        EVP_PKEY_CTX_free(ctx);
    }

end:
    return ret;
}

virtual std::optional<bool> OpEVP_PKEY_Verify(operation::EVP_PKEY_Verify& op) {
    (void)op;
    return std::nullopt;
}
