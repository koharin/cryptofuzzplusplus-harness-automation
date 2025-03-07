#if !defined(CRYPTOFUZZ_BORINGSSL) && !defined(CRYPTOFUZZ_LIBRESSL)

        std::optional<int> OpX509_STORE_CTX_verify(operation::X509_STORE_CTX_verify& op) override;
#endif
