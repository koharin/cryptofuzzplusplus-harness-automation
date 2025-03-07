virtual std::optional<bool> OpEVP_PKEY_Verify(operation::EVP_PKEY_verify& op) {
    std::optional<bool> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    EVP_PKEY_CTX* ctx = nullptr;
    EVP_PKEY* pkey = nullptr;
    const EVP_MD* md = nullptr;

    try {
        // Initialize key and context
        CF_CHECK_NE(pkey = EVP_PKEY_new(), nullptr);
        CF_CHECK_NE(ctx = EVP_PKEY_CTX_new(pkey, nullptr), nullptr);

        // Setting up the public key context for verify operation
        CF_CHECK_EQ(EVP_PKEY_verify_init(ctx), 1);

        // Set padding and digest type
        CF_CHECK_EQ(EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING), 1);
        CF_CHECK_NE(md = toEVPMD(op.digestType), nullptr);
        CF_CHECK_EQ(EVP_PKEY_CTX_set_signature_md(ctx, md), 1);

        // Obtain signature and to-be-signed hash from the datasource
        std::vector<uint8_t> signature = op.cleartext.ToVector();
        std::vector<uint8_t> tbs = util::Digest(op.cleartext, md);

        // Perform the signature verification
        int res = EVP_PKEY_verify(ctx, signature.data(), signature.size(), tbs.data(), tbs.size());

        if (res == 1) {
            ret = true; // Verified successfully
        } else if (res == 0) {
            ret = false; // Verification failed
        } else {
            CF_THROW("Error during EVP_PKEY_verify operation");
        }
    } catch (...) {
        ret = std::nullopt; // Handle any exceptions by returning nullopt
    }

    // Clean up
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);

    return ret;
}
