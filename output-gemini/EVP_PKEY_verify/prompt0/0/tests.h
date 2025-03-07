void test(const operation::Digest& op, const std::optional<component::Digest>& result) {
    using fuzzing::datasource::ID;

    if ( result == std::nullopt ) {
        return;
    }

    /* Do not try to verify truncated digests */
    if ( result->size() < op.digestType.outputSize() ) {
        return;
    }

    std::optional<component::RSA_KeyPair> rsaKeyPair;
    std::optional<component::RSA_PublicKey> rsaPubKey;
    std::optional<component::RSA_PrivateKey> rsaPrivKey;

    std::optional<component::Digest> hash;
    std::optional<component::Signature> signature;

    /* Generate a key */
    {
        operation::RSA_generate_key_ex keygenOp;

        keygenOp.keySize = op.keySize;

        rsaKeyPair = g_openssl.OpRSA_generate_key_ex(keygenOp);
        if ( rsaKeyPair == std::nullopt ) {
            return;
        }
    }

    rsaPubKey = rsaKeyPair->pub;
    rsaPrivKey = rsaKeyPair->priv;

    /* Compute a hash */
    hash = g_openssl.OpDigest(op);
    if ( hash == std::nullopt ) {
        return;
    }

    /* Sign the hash */
    {
        operation::RSA_Sign signOp;

        signOp.digestType = op.digestType;
        signOp.key = rsaPrivKey;
        signOp.cleartext = hash;

        signature = g_openssl.OpRSA_Sign(signOp);
        if ( signature == std::nullopt ) {
            return;
        }
    }

    /* EVP_PKEY_verify */
    {
        EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(rsaPubKey->GetKey(), NULL);
        if ( ctx == nullptr ) {
            return;
        }

        if ( EVP_PKEY_verify_init(ctx) <= 0 ) {
            goto end;
        }

        if ( EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0 ) {
            goto end;
        }

        if ( EVP_PKEY_CTX_set_signature_md(ctx, toEVPMD(op.digestType)) <= 0 ) {
            goto end;
        }

        if ( EVP_PKEY_verify(ctx, signature->data(), signature->size(), hash->data(), hash->size()) != 1 ) {
            abort();
        }

    end:
        EVP_PKEY_CTX_free(ctx);
    }
}
