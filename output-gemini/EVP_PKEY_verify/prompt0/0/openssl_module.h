#if !defined(CRYPTOFUZZ_BORINGSSL) && !defined(CRYPTOFUZZ_LIBRESSL) && !defined(CRYPTOFUZZ_OPENSSL_102) && !defined(CRYPTOFUZZ_OPENSSL_098)
std::optional<bool> OpenSSL::OpECDSA_Verify(operation::ECDSA_Verify& op) override {
    try {
        const EVP_MD* md = toEVPMD(op.digestType);
        if (md == nullptr) {
            return std::nullopt;
        }

        EVP_PKEY* pkey = EVP_PKEY_new();
        if (pkey == nullptr) {
            return std::nullopt;
        }
        if (!EVP_PKEY_set1_EC_KEY(pkey, EC_KEY_dup(op.keyPair.privateKey.Get()))) {
            EVP_PKEY_free(pkey);
            return std::nullopt;
        }

        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, NULL);
        if (ctx == nullptr) {
            EVP_PKEY_free(pkey);
            return std::nullopt;
        }
        if (EVP_PKEY_verify_init(ctx) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            EVP_PKEY_free(pkey);
            return std::nullopt;
        }
        if (EVP_PKEY_CTX_set_signature_md(ctx, md) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            EVP_PKEY_free(pkey);
            return std::nullopt;
        }

        int ret = EVP_PKEY_verify(ctx, op.signature.data(), op.signature.size(),
                                      op.cleartext.data(), op.cleartext.size());

        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);

        if (ret == 1) {
            return true;
        } else if (ret == 0) {
            return false;
        } else {
            return std::nullopt;
        }
    } catch (...) {
        return std::nullopt;
    }
}
#endif
