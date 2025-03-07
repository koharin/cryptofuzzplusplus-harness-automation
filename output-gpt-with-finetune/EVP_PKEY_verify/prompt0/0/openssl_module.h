#if !defined(CRYPTOFUZZ_BORINGSSL) && !defined(CRYPTOFUZZ_OPENSSL_102) && !defined(CRYPTOFUZZ_OPENSSL_098)
        std::optional<bool> OpEVP_PKEY_verify(operation::EVP_PKEY_verify& op) override;
#endif
