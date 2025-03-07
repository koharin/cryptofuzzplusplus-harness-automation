/* Specialization for operation::Digest */
template<> void ExecutorBase<component::Digest, operation::Digest>::postprocess(std::shared_ptr<Module> module, operation::Digest& op, const ExecutorBase<component::Digest, operation::Digest>::ResultPair& result) const {
    (void)module;
    (void)op;

    if ( result.second != std::nullopt ) {
        fuzzing::memory::memory_test_msan(result.second->GetPtr(), result.second->GetSize());
    }
}

template<> std::optional<component::Digest> ExecutorBase<component::Digest, operation::Digest>::callModule(std::shared_ptr<Module> module, operation::Digest& op) const {
    RETURN_IF_DISABLED(options.digests, op.digestType.Get());

    return module->OpDigest(op);
}

/* Specialization for operation::HMAC */
template<> void ExecutorBase<component::MAC, operation::HMAC>::postprocess(std::shared_ptr<Module> module, operation::HMAC& op, const ExecutorBase<component::MAC, operation::HMAC>::ResultPair& result) const {
    (void)module;
    (void)op;

    if ( result.second != std::nullopt ) {
        fuzzing::memory::memory_test_msan(result.second->GetPtr(), result.second->GetSize());
    }
}

template<> std::optional<component::MAC> ExecutorBase<component::MAC, operation::HMAC>::callModule(std::shared_ptr<Module> module, operation::HMAC& op) const {
    RETURN_IF_DISABLED(options.digests, op.digestType.Get());

    return module->OpHMAC(op);
}

/* Specialization for operation::UMAC */
template<> void ExecutorBase<component::MAC, operation::UMAC>::postprocess(std::shared_ptr<Module> module, operation::UMAC& op, const ExecutorBase<component::MAC, operation::UMAC>::ResultPair& result) const {
    (void)module;
    (void)op;

    if ( result.second != std::nullopt ) {
        fuzzing::memory::memory_test_msan(result.second->GetPtr(), result.second->GetSize());
    }
}

template<> std::optional<component::MAC> ExecutorBase<component::MAC, operation::UMAC>::callModule(std::shared_ptr<Module> module, operation::UMAC& op) const {
    return module->OpUMAC(op);
}

/* Specialization for operation::CMAC */
template<> void ExecutorBase<component::MAC, operation::CMAC>::postprocess(std::shared_ptr<Module> module, operation::CMAC& op, const ExecutorBase<component::MAC, operation::CMAC>::ResultPair& result) const {
    (void)module;
    (void)op;

    if ( result.second != std::nullopt ) {
        fuzzing::memory::memory_test_msan(result.second->GetPtr(), result.second->GetSize());
    }
}

template<> std::optional<component::MAC> ExecutorBase<component::MAC, operation::CMAC>::callModule(std::shared_ptr<Module> module, operation::CMAC& op) const {
    RETURN_IF_DISABLED(options.ciphers, op.cipher.cipherType.Get());

    return module->OpCMAC(op);
}

/* Specialization for operation::SymmetricEncrypt */
template<> void ExecutorBase<component::Ciphertext, operation::SymmetricEncrypt>::postprocess(std::shared_ptr<Module> module, operation::SymmetricEncrypt& op, const ExecutorBase<component::Ciphertext, operation::SymmetricEncrypt>::ResultPair& result) const {
    if ( options.noDecrypt == true ) {
        return;
    }

    if ( result.second != std::nullopt ) {
        fuzzing::memory::memory_test_msan(result.second->ciphertext.GetPtr(), result.second->ciphertext.GetSize());
        if ( result.second->tag != std::nullopt ) {
            fuzzing::memory::memory_test_msan(result.second->tag->GetPtr(), result.second->tag->GetSize());
        }
    }

    if ( op.cleartext.GetSize() > 0 && result.second != std::nullopt && result.second->ciphertext.GetSize() > 0 ) {
        using fuzzing::datasource::ID;

        bool tryDecrypt = true;

        if ( module->ID == CF_MODULE("OpenSSL") ) {
            switch ( op.cipher.cipherType.Get() ) {
                case    ID("Cryptofuzz/Cipher/AES_128_OCB"):
                case    ID("Cryptofuzz/Cipher/AES_256_OCB"):
                    tryDecrypt = false;
                    break;
                case    ID("Cryptofuzz/Cipher/AES_128_GCM"):
                case    ID("Cryptofuzz/Cipher/AES_192_GCM"):
                case    ID("Cryptofuzz/Cipher/AES_256_GCM"):
                case    ID("Cryptofuzz/Cipher/AES_128_CCM"):
                case    ID("Cryptofuzz/Cipher/AES_192_CCM"):
                case    ID("Cryptofuzz/Cipher/AES_256_CCM"):
                case    ID("Cryptofuzz/Cipher/ARIA_128_CCM"):
                case    ID("Cryptofuzz/Cipher/ARIA_192_CCM"):
                case    ID("Cryptofuzz/Cipher/ARIA_256_CCM"):
                case    ID("Cryptofuzz/Cipher/ARIA_128_GCM"):
                case    ID("Cryptofuzz/Cipher/ARIA_192_GCM"):
                case    ID("Cryptofuzz/Cipher/ARIA_256_GCM"):
                    if ( op.tagSize == std::nullopt ) {
                        /* OpenSSL fails to decrypt its own CCM and GCM ciphertexts if
                         * a tag is not included
                         */
                        tryDecrypt = false;
                    }
                    break;
            }
        }

        if ( tryDecrypt == true ) {
            /* Try to decrypt the encrypted data */

            /* Construct a SymmetricDecrypt instance with the SymmetricEncrypt instance */
            auto opDecrypt = operation::SymmetricDecrypt(
                    /* The SymmetricEncrypt instance */
                    op,

                    /* The ciphertext generated by OpSymmetricEncrypt */
                    *(result.second),

                    /* The size of the output buffer that OpSymmetricDecrypt() must use. */
                    op.cleartext.GetSize() + 32,

                    op.aad,

                    /* Empty modifier */
                    {});

            const auto cleartext = module->OpSymmetricDecrypt(opDecrypt);

            if ( cleartext == std::nullopt ) {
                /* Decryption failed, OpSymmetricDecrypt() returned std::nullopt */
                printf("Cannot decrypt ciphertext\n\n");
                printf("Operation:\n%s\n", op.ToString().c_str());
                printf("Ciphertext: %s\n", util::HexDump(result.second->ciphertext.Get()).c_str());
                printf("Tag: %s\n", result.second->tag ? util::HexDump(result.second->tag->Get()).c_str() : "nullopt");
                abort(
                        {module->name},
                        op.Name(),
                        op.GetAlgorithmString(),
                        "cannot decrypt ciphertext"
                );
            } else if ( cleartext->Get() != op.cleartext.Get() ) {
                /* Decryption ostensibly succeeded, but the cleartext returned by OpSymmetricDecrypt()
                 * does not match to original cleartext */

                printf("Cannot decrypt ciphertext (but decryption ostensibly succeeded)\n\n");
                printf("Operation:\n%s\n", op.ToString().c_str());
                printf("Ciphertext: %s\n", util::HexDump(result.second->ciphertext.Get()).c_str());
                printf("Tag: %s\n", result.second->tag ? util::HexDump(result.second->tag->Get()).c_str() : "nullopt");
                printf("Purported cleartext: %s\n", util::HexDump(cleartext->Get()).c_str());
                abort(
                        {module->name},
                        op.Name(),
                        op.GetAlgorithmString(),
                        "cannot decrypt ciphertext"
                );
            }
        }
    }
}

template<> std::optional<component::Ciphertext> ExecutorBase<component::Ciphertext, operation::SymmetricEncrypt>::callModule(std::shared_ptr<Module> module, operation::SymmetricEncrypt& op) const {
    RETURN_IF_DISABLED(options.ciphers , op.cipher.cipherType.Get());

    return module->OpSymmetricEncrypt(op);
}

/* Specialization for operation::SymmetricDecrypt */
template<> void ExecutorBase<component::MAC, operation::SymmetricDecrypt>::postprocess(std::shared_ptr<Module> module, operation::SymmetricDecrypt& op, const ExecutorBase<component::MAC, operation::SymmetricDecrypt>::ResultPair& result) const {
    (void)module;
    (void)op;

    if ( result.second != std::nullopt ) {
        fuzzing::memory::memory_test_msan(result.second->GetPtr(), result.second->GetSize());
    }
}

template<> std::optional<component::MAC> ExecutorBase<component::MAC, operation::SymmetricDecrypt>::callModule(std::shared_ptr<Module> module, operation::SymmetricDecrypt& op) const {
    RETURN_IF_DISABLED(options.ciphers , op.cipher.cipherType.Get());

    return module->OpSymmetricDecrypt(op);
}

/* Specialization for operation::KDF_SCRYPT */
template<> void ExecutorBase<component::Key, operation::KDF_SCRYPT>::postprocess(std::shared_ptr<Module> module, operation::KDF_SCRYPT& op, const ExecutorBase<component::Key, operation::KDF_SCRYPT>::ResultPair& result) const {
    (void)module;
    (void)op;

    if ( result.second != std::nullopt ) {
        fuzzing::memory::memory_test_msan(result.second->GetPtr(), result.second->GetSize());
    }
}

template<> std::optional<component::Key> ExecutorBase<component::Key, operation::KDF_SCRYPT>::callModule(std::shared_ptr<Module> module, operation::KDF_SCRYPT& op) const {
    return module->OpKDF_SCRYPT(op);
}

/* Specialization for operation::KDF_HKDF */
template<> void ExecutorBase<component::Key, operation::KDF_HKDF>::postprocess(std::shared_ptr<Module> module, operation::KDF_HKDF& op, const ExecutorBase<component::Key, operation::KDF_HKDF>::ResultPair& result) const {
    (void)module;
    (void)op;

    if ( result.second != std::nullopt ) {
        fuzzing::memory::memory_test_msan(result.second->GetPtr(), result.second->GetSize());
    }
}

template<> std::optional<component::Key> ExecutorBase<component::Key, operation::KDF_HKDF>::callModule(std::shared_ptr<Module> module, operation::KDF_HKDF& op) const {
    RETURN_IF_DISABLED(options.digests, op.digestType.Get());

    return module->OpKDF_HKDF(op);
}

/* Specialization for operation::KDF_PBKDF */
template<> void ExecutorBase<component::Key, operation::KDF_PBKDF>::postprocess(std::shared_ptr<Module> module, operation::KDF_PBKDF& op, const ExecutorBase<component::Key, operation::KDF_PBKDF>::ResultPair& result) const {
    (void)module;
    (void)op;

    if ( result.second != std::nullopt ) {
        fuzzing::memory::memory_test_msan(result.second->GetPtr(), result.second->GetSize());
    }
}

template<> std::optional<component::Key> ExecutorBase<component::Key, operation::KDF_PBKDF>::callModule(std::shared_ptr<Module> module, operation::KDF_PBKDF& op) const {
    RETURN_IF_DISABLED(options.digests, op.digestType.Get());

    return module->OpKDF_PBKDF(op);
}

/* Specialization for operation::KDF_PBKDF1 */
template<> void ExecutorBase<component::Key, operation::KDF_PBKDF1>::postprocess(std::shared_ptr<Module> module, operation::KDF_PBKDF1& op, const ExecutorBase<component::Key, operation::KDF_PBKDF1>::ResultPair& result) const {
    (void)module;
    (void)op;

    if ( result.second != std::nullopt ) {
        fuzzing::memory::memory_test_msan(result.second->GetPtr(), result.second->GetSize());
    }
}

template<> std::optional<component::Key> ExecutorBase<component::Key, operation::KDF_PBKDF1>::callModule(std::shared_ptr<Module> module, operation::KDF_PBKDF1& op) const {
    RETURN_IF_DISABLED(options.digests, op.digestType.Get());

    return module->OpKDF_PBKDF1(op);
}

/* Specialization for operation::KDF_PBKDF2 */
template<> void ExecutorBase<component::Key, operation::KDF_PBKDF2>::postprocess(std::shared_ptr<Module> module, operation::KDF_PBKDF2& op, const ExecutorBase<component::Key, operation::KDF_PBKDF2>::ResultPair& result) const {
    (void)module;
    (void)op;

    if ( result.second != std::nullopt ) {
        fuzzing::memory::memory_test_msan(result.second->GetPtr(), result.second->GetSize());
    }
}

template<> std::optional<component::Key> ExecutorBase<component::Key, operation::KDF_PBKDF2>::callModule(std::shared_ptr<Module> module, operation::KDF_PBKDF2& op) const {
    RETURN_IF_DISABLED(options.digests, op.digestType.Get());

    return module->OpKDF_PBKDF2(op);
}

/* Specialization for operation::KDF_ARGON2 */
template<> void ExecutorBase<component::Key, operation::KDF_ARGON2>::postprocess(std::shared_ptr<Module> module, operation::KDF_ARGON2& op, const ExecutorBase<component::Key, operation::KDF_ARGON2>::ResultPair& result) const {
    (void)module;
    (void)op;

    if ( result.second != std::nullopt ) {
        fuzzing::memory::memory_test_msan(result.second->GetPtr(), result.second->GetSize());
    }
}

template<> std::optional<component::Key> ExecutorBase<component::Key, operation::KDF_ARGON2>::callModule(std::shared_ptr<Module> module, operation::KDF_ARGON2& op) const {
    return module->OpKDF_ARGON2(op);
}

/* Specialization for operation::KDF_SSH */
template<> void ExecutorBase<component::Key, operation::KDF_SSH>::postprocess(std::shared_ptr<Module> module, operation::KDF_SSH& op, const ExecutorBase<component::Key, operation::KDF_SSH>::ResultPair& result) const {
    (void)module;
    (void)op;

    if ( result.second != std::nullopt ) {
        fuzzing::memory::memory_test_msan(result.second->GetPtr(), result.second->GetSize());
    }
}

template<> std::optional<component::Key> ExecutorBase<component::Key, operation::KDF_SSH>::callModule(std::shared_ptr<Module> module, operation::KDF_SSH& op) const {
    RETURN_IF_DISABLED(options.digests, op.digestType.Get());

    return module->OpKDF_SSH(op);
}

/* Specialization for operation::KDF_TLS1_PRF */
template<> void ExecutorBase<component::Key, operation::KDF_TLS1_PRF>::postprocess(std::shared_ptr<Module> module, operation::KDF_TLS1_PRF& op, const ExecutorBase<component::Key, operation::KDF_TLS1_PRF>::ResultPair& result) const {
    (void)module;
    (void)op;

    if ( result.second != std::nullopt ) {
        fuzzing::memory::memory_test_msan(result.second->GetPtr(), result.second->GetSize());
    }
}

template<> std::optional<component::Key> ExecutorBase<component::Key, operation::KDF_TLS1_PRF>::callModule(std::shared_ptr<Module> module, operation::KDF_TLS1_PRF& op) const {
    RETURN_IF_DISABLED(options.digests, op.digestType.Get());

    return module->OpKDF_TLS1_PRF(op);
}

/* Specialization for operation::KDF_X963 */
template<> void ExecutorBase<component::Key, operation::KDF_X963>::postprocess(std::shared_ptr<Module> module, operation::KDF_X963& op, const ExecutorBase<component::Key, operation::KDF_X963>::ResultPair& result) const {
    (void)module;
    (void)op;

    if ( result.second != std::nullopt ) {
        fuzzing::memory::memory_test_msan(result.second->GetPtr(), result.second->GetSize());
    }
}

template<> std::optional<component::Key> ExecutorBase<component::Key, operation::KDF_X963>::callModule(std::shared_ptr<Module> module, operation::KDF_X963& op) const {
    RETURN_IF_DISABLED(options.digests, op.digestType.Get());

    return module->OpKDF_X963(op);
}

/* Specialization for operation::KDF_BCRYPT */
template<> void ExecutorBase<component::Key, operation::KDF_BCRYPT>::postprocess(std::shared_ptr<Module> module, operation::KDF_BCRYPT& op, const ExecutorBase<component::Key, operation::KDF_BCRYPT>::ResultPair& result) const {
    (void)module;
    (void)op;

    if ( result.second != std::nullopt ) {
        fuzzing::memory::memory_test_msan(result.second->GetPtr(), result.second->GetSize());
    }
}

template<> std::optional<component::Key> ExecutorBase<component::Key, operation::KDF_BCRYPT>::callModule(std::shared_ptr<Module> module, operation::KDF_BCRYPT& op) const {
    RETURN_IF_DISABLED(options.digests, op.digestType.Get());

    return module->OpKDF_BCRYPT(op);
}

/* Specialization for operation::KDF_SP_800_108 */
template<> void ExecutorBase<component::Key, operation::KDF_SP_800_108>::postprocess(std::shared_ptr<Module> module, operation::KDF_SP_800_108& op, const ExecutorBase<component::Key, operation::KDF_SP_800_108>::ResultPair& result) const {
    (void)module;
    (void)op;

    if ( result.second != std::nullopt ) {
        fuzzing::memory::memory_test_msan(result.second->GetPtr(), result.second->GetSize());
    }
}

template<> std::optional<component::Key> ExecutorBase<component::Key, operation::KDF_SP_800_108>::callModule(std::shared_ptr<Module> module, operation::KDF_SP_800_108& op) const {
    if ( op.mech.mode == true ) {
        RETURN_IF_DISABLED(options.digests, op.mech.type.Get());
    }

    return module->OpKDF_SP_800_108(op);
}


/* Specialization for operation::ECC_PrivateToPublic */
template<> void ExecutorBase<component::ECC_PublicKey, operation::ECC_PrivateToPublic>::postprocess(std::shared_ptr<Module> module, operation::ECC_PrivateToPublic& op, const ExecutorBase<component::ECC_PublicKey, operation::ECC_PrivateToPublic>::ResultPair& result) const {
    (void)module;

    if ( result.second != std::nullopt  ) {
        const auto curveID = op.curveType.Get();
        const auto privkey = op.priv.ToTrimmedString();
        const auto pub_x = result.second->first.ToTrimmedString();
        const auto pub_y = result.second->second.ToTrimmedString();

        Pool_CurvePrivkey.Set({ curveID, privkey });
        Pool_CurveKeypair.Set({ curveID, privkey, pub_x, pub_y });
        Pool_CurveECC_Point.Set({ curveID, pub_x, pub_y });

        if ( pub_x.size() <= config::kMaxBignumSize ) { Pool_Bignum.Set(pub_x); }
        if ( pub_y.size() <= config::kMaxBignumSize ) { Pool_Bignum.Set(pub_y); }
    }
}

template<> std::optional<component::ECC_PublicKey> ExecutorBase<component::ECC_PublicKey, operation::ECC_PrivateToPublic>::callModule(std::shared_ptr<Module> module, operation::ECC_PrivateToPublic& op) const {
    RETURN_IF_DISABLED(options.curves, op.curveType.Get());

    const size_t size = op.priv.ToTrimmedString().size();

    if ( size == 0 || size > 4096 ) {
        return std::nullopt;
    }

    return module->OpECC_PrivateToPublic(op);
}

/* Specialization for operation::ECC_ValidatePubkey */
template<> void ExecutorBase<bool, operation::ECC_ValidatePubkey>::postprocess(std::shared_ptr<Module> module, operation::ECC_ValidatePubkey& op, const ExecutorBase<bool, operation::ECC_ValidatePubkey>::ResultPair& result) const {
    (void)module;
    (void)op;
    (void)result;
}

template<> std::optional<bool> ExecutorBase<bool, operation::ECC_ValidatePubkey>::callModule(std::shared_ptr<Module> module, operation::ECC_ValidatePubkey& op) const {
    RETURN_IF_DISABLED(options.curves, op.curveType.Get());

    return module->OpECC_ValidatePubkey(op);
}

/* Specialization for operation::ECC_GenerateKeyPair */

/* Do not compare DH_GenerateKeyPair results, because the result can be produced indeterministically */
template <>
void ExecutorBase<component::DH_KeyPair, operation::DH_GenerateKeyPair>::compare(const std::vector< std::pair<std::shared_ptr<Module>, operation::DH_GenerateKeyPair> >& operations, const ResultSet& results, const uint8_t* data, const size_t size) const {
    (void)operations;
    (void)results;
    (void)data;
    (void)size;
}

template<> void ExecutorBase<component::ECC_KeyPair, operation::ECC_GenerateKeyPair>::postprocess(std::shared_ptr<Module> module, operation::ECC_GenerateKeyPair& op, const ExecutorBase<component::ECC_KeyPair, operation::ECC_GenerateKeyPair>::ResultPair& result) const {
    (void)module;

    if ( result.second != std::nullopt  ) {
        const auto curveID = op.curveType.Get();
        const auto privkey = result.second->priv.ToTrimmedString();
        const auto pub_x = result.second->pub.first.ToTrimmedString();
        const auto pub_y = result.second->pub.second.ToTrimmedString();

        Pool_CurvePrivkey.Set({ curveID, privkey });
        Pool_CurveKeypair.Set({ curveID, privkey, pub_x, pub_y });
        Pool_CurveECC_Point.Set({ curveID, pub_x, pub_y });
    }
}

template<> std::optional<component::ECC_KeyPair> ExecutorBase<component::ECC_KeyPair, operation::ECC_GenerateKeyPair>::callModule(std::shared_ptr<Module> module, operation::ECC_GenerateKeyPair& op) const {
    RETURN_IF_DISABLED(options.curves, op.curveType.Get());

    return module->OpECC_GenerateKeyPair(op);
}

/* Specialization for operation::ECDSA_Sign */
template<> void ExecutorBase<component::ECDSA_Signature, operation::ECDSA_Sign>::postprocess(std::shared_ptr<Module> module, operation::ECDSA_Sign& op, const ExecutorBase<component::ECDSA_Signature, operation::ECDSA_Sign>::ResultPair& result) const {
    (void)module;

    if ( result.second != std::nullopt  ) {
        const auto curveID = op.curveType.Get();
        const auto cleartext = op.cleartext.ToHex();
        const auto pub_x = result.second->pub.first.ToTrimmedString();
        const auto pub_y = result.second->pub.second.ToTrimmedString();
        const auto sig_r = result.second->signature.first.ToTrimmedString();
        const auto sig_s = result.second->signature.second.ToTrimmedString();

        Pool_CurveECDSASignature.Set({ curveID, cleartext, pub_x, pub_y, sig_r, sig_s});
        Pool_CurveECC_Point.Set({ curveID, pub_x, pub_y });
        Pool_CurveECC_Point.Set({ curveID, sig_r, sig_s });

        if ( pub_x.size() <= config::kMaxBignumSize ) { Pool_Bignum.Set(pub_x); }
        if ( pub_y.size() <= config::kMaxBignumSize ) { Pool_Bignum.Set(pub_y); }
        if ( sig_r.size() <= config::kMaxBignumSize ) { Pool_Bignum.Set(sig_r); }
        if ( sig_s.size() <= config::kMaxBignumSize ) { Pool_Bignum.Set(sig_s); }

        {
            auto opVerify = operation::ECDSA_Verify(
                    op,
                    *(result.second),
                    op.modifier);

            const auto verifyResult = module->OpECDSA_Verify(opVerify);
            CF_ASSERT(
                    verifyResult == std::nullopt ||
                    *verifyResult == true,
                    "Cannot verify generated signature");
        }
    }
}

template<> std::optional<component::ECDSA_Signature> ExecutorBase<component::ECDSA_Signature, operation::ECDSA_Sign>::callModule(std::shared_ptr<Module> module, operation::ECDSA_Sign& op) const {
    RETURN_IF_DISABLED(options.curves, op.curveType.Get());
    RETURN_IF_DISABLED(options.digests, op.digestType.Get());

    const size_t size = op.priv.ToTrimmedString().size();

    if ( size == 0 || size > 4096 ) {
        return std::nullopt;
    }

    return module->OpECDSA_Sign(op);
}

/* Specialization for operation::ECGDSA_Sign */
template<> void ExecutorBase<component::ECGDSA_Signature, operation::ECGDSA_Sign>::postprocess(std::shared_ptr<Module> module, operation::ECGDSA_Sign& op, const ExecutorBase<component::ECGDSA_Signature, operation::ECGDSA_Sign>::ResultPair& result) const {
    (void)module;

    if ( result.second != std::nullopt  ) {
        const auto curveID = op.curveType.Get();
        const auto cleartext = op.cleartext.ToHex();
        const auto pub_x = result.second->pub.first.ToTrimmedString();
        const auto pub_y = result.second->pub.second.ToTrimmedString();
        const auto sig_r = result.second->signature.first.ToTrimmedString();
        const auto sig_s = result.second->signature.second.ToTrimmedString();

        Pool_CurveECDSASignature.Set({ curveID, cleartext, pub_x, pub_y, sig_r, sig_s});
        Pool_CurveECC_Point.Set({ curveID, pub_x, pub_y });
        Pool_CurveECC_Point.Set({ curveID, sig_r, sig_s });

        if ( pub_x.size() <= config::kMaxBignumSize ) { Pool_Bignum.Set(pub_x); }
        if ( pub_y.size() <= config::kMaxBignumSize ) { Pool_Bignum.Set(pub_y); }
        if ( sig_r.size() <= config::kMaxBignumSize ) { Pool_Bignum.Set(sig_r); }
        if ( sig_s.size() <= config::kMaxBignumSize ) { Pool_Bignum.Set(sig_s); }
    }
}

template<> std::optional<component::ECGDSA_Signature> ExecutorBase<component::ECGDSA_Signature, operation::ECGDSA_Sign>::callModule(std::shared_ptr<Module> module, operation::ECGDSA_Sign& op) const {
    RETURN_IF_DISABLED(options.curves, op.curveType.Get());
    RETURN_IF_DISABLED(options.digests, op.digestType.Get());

    const size_t size = op.priv.ToTrimmedString().size();

    if ( size == 0 || size > 4096 ) {
        return std::nullopt;
    }

    return module->OpECGDSA_Sign(op);
}

/* Specialization for operation::ECRDSA_Sign */
template<> void ExecutorBase<component::ECRDSA_Signature, operation::ECRDSA_Sign>::postprocess(std::shared_ptr<Module> module, operation::ECRDSA_Sign& op, const ExecutorBase<component::ECRDSA_Signature, operation::ECRDSA_Sign>::ResultPair& result) const {
    (void)module;

    if ( result.second != std::nullopt  ) {
        const auto curveID = op.curveType.Get();
        const auto cleartext = op.cleartext.ToHex();
        const auto pub_x = result.second->pub.first.ToTrimmedString();
        const auto pub_y = result.second->pub.second.ToTrimmedString();
        const auto sig_r = result.second->signature.first.ToTrimmedString();
        const auto sig_s = result.second->signature.second.ToTrimmedString();

        Pool_CurveECDSASignature.Set({ curveID, cleartext, pub_x, pub_y, sig_r, sig_s});
        Pool_CurveECC_Point.Set({ curveID, pub_x, pub_y });
        Pool_CurveECC_Point.Set({ curveID, sig_r, sig_s });

        if ( pub_x.size() <= config::kMaxBignumSize ) { Pool_Bignum.Set(pub_x); }
        if ( pub_y.size() <= config::kMaxBignumSize ) { Pool_Bignum.Set(pub_y); }
        if ( sig_r.size() <= config::kMaxBignumSize ) { Pool_Bignum.Set(sig_r); }
        if ( sig_s.size() <= config::kMaxBignumSize ) { Pool_Bignum.Set(sig_s); }
    }
}

template<> std::optional<component::ECRDSA_Signature> ExecutorBase<component::ECRDSA_Signature, operation::ECRDSA_Sign>::callModule(std::shared_ptr<Module> module, operation::ECRDSA_Sign& op) const {
    RETURN_IF_DISABLED(options.curves, op.curveType.Get());
    RETURN_IF_DISABLED(options.digests, op.digestType.Get());

    const size_t size = op.priv.ToTrimmedString().size();

    if ( size == 0 || size > 4096 ) {
        return std::nullopt;
    }

    return module->OpECRDSA_Sign(op);
}

/* Specialization for operation::Schnorr_Sign */
template<> void ExecutorBase<component::Schnorr_Signature, operation::Schnorr_Sign>::postprocess(std::shared_ptr<Module> module, operation::Schnorr_Sign& op, const ExecutorBase<component::Schnorr_Signature, operation::Schnorr_Sign>::ResultPair& result) const {
    (void)module;

    if ( result.second != std::nullopt  ) {
        const auto curveID = op.curveType.Get();
        const auto cleartext = op.cleartext.ToHex();
        const auto pub_x = result.second->pub.first.ToTrimmedString();
        const auto pub_y = result.second->pub.second.ToTrimmedString();
        const auto sig_r = result.second->signature.first.ToTrimmedString();
        const auto sig_s = result.second->signature.second.ToTrimmedString();

        Pool_CurveECDSASignature.Set({ curveID, cleartext, pub_x, pub_y, sig_r, sig_s});
        Pool_CurveECC_Point.Set({ curveID, pub_x, pub_y });
        Pool_CurveECC_Point.Set({ curveID, sig_r, sig_s });

        if ( pub_x.size() <= config::kMaxBignumSize ) { Pool_Bignum.Set(pub_x); }
        if ( pub_y.size() <= config::kMaxBignumSize ) { Pool_Bignum.Set(pub_y); }
        if ( sig_r.size() <= config::kMaxBignumSize ) { Pool_Bignum.Set(sig_r); }
        if ( sig_s.size() <= config::kMaxBignumSize ) { Pool_Bignum.Set(sig_s); }
    }
}

template<> std::optional<component::Schnorr_Signature> ExecutorBase<component::Schnorr_Signature, operation::Schnorr_Sign>::callModule(std::shared_ptr<Module> module, operation::Schnorr_Sign& op) const {
    RETURN_IF_DISABLED(options.curves, op.curveType.Get());
    RETURN_IF_DISABLED(options.digests, op.digestType.Get());

    const size_t size = op.priv.ToTrimmedString().size();

    if ( size == 0 || size > 4096 ) {
        return std::nullopt;
    }

    return module->OpSchnorr_Sign(op);
}

/* Specialization for operation::ECDSA_Verify */
template<> void ExecutorBase<bool, operation::ECDSA_Verify>::postprocess(std::shared_ptr<Module> module, operation::ECDSA_Verify& op, const ExecutorBase<bool, operation::ECDSA_Verify>::ResultPair& result) const {
    (void)module;
    (void)op;
    (void)result;
}

template<> std::optional<bool> ExecutorBase<bool, operation::ECDSA_Verify>::callModule(std::shared_ptr<Module> module, operation::ECDSA_Verify& op) const {
    RETURN_IF_DISABLED(options.curves, op.curveType.Get());
    RETURN_IF_DISABLED(options.digests, op.digestType.Get());

    /* Intentionally do not constrain the size of the public key or
     * signature (like we do for BignumCalc).
     *
     * If any large public key or signature causes a time-out (or
     * worse), this is something that needs attention;
     * because verifiers sometimes process untrusted public keys,
     * signatures or both, they should be resistant to bugs
     * arising from large inputs.
     */

    return module->OpECDSA_Verify(op);
}

/* Specialization for operation::ECGDSA_Verify */
template<> void ExecutorBase<bool, operation::ECGDSA_Verify>::postprocess(std::shared_ptr<Module> module, operation::ECGDSA_Verify& op, const ExecutorBase<bool, operation::ECGDSA_Verify>::ResultPair& result) const {
    (void)module;
    (void)op;
    (void)result;
}

template<> std::optional<bool> ExecutorBase<bool, operation::ECGDSA_Verify>::callModule(std::shared_ptr<Module> module, operation::ECGDSA_Verify& op) const {
    RETURN_IF_DISABLED(options.curves, op.curveType.Get());
    RETURN_IF_DISABLED(options.digests, op.digestType.Get());

    /* Intentionally do not constrain the size of the public key or
     * signature (like we do for BignumCalc).
     *
     * If any large public key or signature causes a time-out (or
     * worse), this is something that needs attention;
     * because verifiers sometimes process untrusted public keys,
     * signatures or both, they should be resistant to bugs
     * arising from large inputs.
     */

    return module->OpECGDSA_Verify(op);
}

/* Specialization for operation::ECRDSA_Verify */
template<> void ExecutorBase<bool, operation::ECRDSA_Verify>::postprocess(std::shared_ptr<Module> module, operation::ECRDSA_Verify& op, const ExecutorBase<bool, operation::ECRDSA_Verify>::ResultPair& result) const {
    (void)module;
    (void)op;
    (void)result;
}

template<> std::optional<bool> ExecutorBase<bool, operation::ECRDSA_Verify>::callModule(std::shared_ptr<Module> module, operation::ECRDSA_Verify& op) const {
    RETURN_IF_DISABLED(options.curves, op.curveType.Get());
    RETURN_IF_DISABLED(options.digests, op.digestType.Get());

    /* Intentionally do not constrain the size of the public key or
     * signature (like we do for BignumCalc).
     *
     * If any large public key or signature causes a time-out (or
     * worse), this is something that needs attention;
     * because verifiers sometimes process untrusted public keys,
     * signatures or both, they should be resistant to bugs
     * arising from large inputs.
     */

    return module->OpECRDSA_Verify(op);
}

/* Specialization for operation::Schnorr_Verify */
template<> void ExecutorBase<bool, operation::Schnorr_Verify>::postprocess(std::shared_ptr<Module> module, operation::Schnorr_Verify& op, const ExecutorBase<bool, operation::Schnorr_Verify>::ResultPair& result) const {
    (void)module;
    (void)op;
    (void)result;
}

template<> std::optional<bool> ExecutorBase<bool, operation::Schnorr_Verify>::callModule(std::shared_ptr<Module> module, operation::Schnorr_Verify& op) const {
    RETURN_IF_DISABLED(options.curves, op.curveType.Get());
    RETURN_IF_DISABLED(options.digests, op.digestType.Get());

    /* Intentionally do not constrain the size of the public key or
     * signature (like we do for BignumCalc).
     *
     * If any large public key or signature causes a time-out (or
     * worse), this is something that needs attention;
     * because verifiers sometimes process untrusted public keys,
     * signatures or both, they should be resistant to bugs
     * arising from large inputs.
     */

    return module->OpSchnorr_Verify(op);
}

template<> void ExecutorBase<component::ECC_PublicKey, operation::ECDSA_Recover>::postprocess(std::shared_ptr<Module> module, operation::ECDSA_Recover& op, const ExecutorBase<component::ECC_PublicKey, operation::ECDSA_Recover>::ResultPair& result) const {
    (void)module;
    (void)op;
    (void)result;
}

template<> std::optional<component::ECC_PublicKey> ExecutorBase<component::ECC_PublicKey, operation::ECDSA_Recover>::callModule(std::shared_ptr<Module> module, operation::ECDSA_Recover& op) const {
    RETURN_IF_DISABLED(options.curves, op.curveType.Get());
    RETURN_IF_DISABLED(options.digests, op.digestType.Get());

    return module->OpECDSA_Recover(op);
}

/* Specialization for operation::ECDH_Derive */
template<> void ExecutorBase<component::Secret, operation::ECDH_Derive>::postprocess(std::shared_ptr<Module> module, operation::ECDH_Derive& op, const ExecutorBase<component::Secret, operation::ECDH_Derive>::ResultPair& result) const {
    (void)module;
    (void)op;
    (void)result;
}

template<> std::optional<component::Secret> ExecutorBase<component::Secret, operation::ECDH_Derive>::callModule(std::shared_ptr<Module> module, operation::ECDH_Derive& op) const {
    RETURN_IF_DISABLED(options.curves, op.curveType.Get());

    return module->OpECDH_Derive(op);
}

/* Specialization for operation::ECIES_Encrypt */
template<> void ExecutorBase<component::Ciphertext, operation::ECIES_Encrypt>::postprocess(std::shared_ptr<Module> module, operation::ECIES_Encrypt& op, const ExecutorBase<component::Ciphertext, operation::ECIES_Encrypt>::ResultPair& result) const {
    (void)module;
    (void)op;
    (void)result;
}

template<> std::optional<component::Ciphertext> ExecutorBase<component::Ciphertext, operation::ECIES_Encrypt>::callModule(std::shared_ptr<Module> module, operation::ECIES_Encrypt& op) const {
    RETURN_IF_DISABLED(options.curves, op.curveType.Get());

    return module->OpECIES_Encrypt(op);
}

/* Specialization for operation::ECIES_Decrypt */
template<> void ExecutorBase<component::Cleartext, operation::ECIES_Decrypt>::postprocess(std::shared_ptr<Module> module, operation::ECIES_Decrypt& op, const ExecutorBase<component::Cleartext, operation::ECIES_Decrypt>::ResultPair& result) const {
    (void)module;
    (void)op;
    (void)result;
}

template<> std::optional<component::Cleartext> ExecutorBase<component::Cleartext, operation::ECIES_Decrypt>::callModule(std::shared_ptr<Module> module, operation::ECIES_Decrypt& op) const {
    RETURN_IF_DISABLED(options.curves, op.curveType.Get());

    return module->OpECIES_Decrypt(op);
}

/* Specialization for operation::ECC_Point_Add */
template<> void ExecutorBase<component::ECC_Point, operation::ECC_Point_Add>::postprocess(std::shared_ptr<Module> module, operation::ECC_Point_Add& op, const ExecutorBase<component::ECC_Point, operation::ECC_Point_Add>::ResultPair& result) const {
    (void)module;

    if ( result.second != std::nullopt  ) {
        const auto curveID = op.curveType.Get();
        const auto x = result.second->first.ToTrimmedString();
        const auto y = result.second->second.ToTrimmedString();

        Pool_CurveECC_Point.Set({ curveID, x, y });

        if ( x.size() <= config::kMaxBignumSize ) { Pool_Bignum.Set(x); }
        if ( y.size() <= config::kMaxBignumSize ) { Pool_Bignum.Set(y); }
    }
}

template<> std::optional<component::ECC_Point> ExecutorBase<component::ECC_Point, operation::ECC_Point_Add>::callModule(std::shared_ptr<Module> module, operation::ECC_Point_Add& op) const {
    RETURN_IF_DISABLED(options.curves, op.curveType.Get());

    return module->OpECC_Point_Add(op);
}

/* Specialization for operation::ECC_Point_Mul */
template<> void ExecutorBase<component::ECC_Point, operation::ECC_Point_Mul>::postprocess(std::shared_ptr<Module> module, operation::ECC_Point_Mul& op, const ExecutorBase<component::ECC_Point, operation::ECC_Point_Mul>::ResultPair& result) const {
    (void)module;

    if ( result.second != std::nullopt  ) {
        const auto curveID = op.curveType.Get();
        const auto x = result.second->first.ToTrimmedString();
        const auto y = result.second->second.ToTrimmedString();

        Pool_CurveECC_Point.Set({ curveID, x, y });

        if ( x.size() <= config::kMaxBignumSize ) { Pool_Bignum.Set(x); }
        if ( y.size() <= config::kMaxBignumSize ) { Pool_Bignum.Set(y); }
    }
}

template<> std::optional<component::ECC_Point> ExecutorBase<component::ECC_Point, operation::ECC_Point_Mul>::callModule(std::shared_ptr<Module> module, operation::ECC_Point_Mul& op) const {
    RETURN_IF_DISABLED(options.curves, op.curveType.Get());

    return module->OpECC_Point_Mul(op);
}

/* Specialization for operation::ECC_Point_Neg */
template<> void ExecutorBase<component::ECC_Point, operation::ECC_Point_Neg>::postprocess(std::shared_ptr<Module> module, operation::ECC_Point_Neg& op, const ExecutorBase<component::ECC_Point, operation::ECC_Point_Neg>::ResultPair& result) const {
    (void)module;

    if ( result.second != std::nullopt  ) {
        const auto curveID = op.curveType.Get();
        const auto x = result.second->first.ToTrimmedString();
        const auto y = result.second->second.ToTrimmedString();

        Pool_CurveECC_Point.Set({ curveID, x, y });

        if ( x.size() <= config::kMaxBignumSize ) { Pool_Bignum.Set(x); }
        if ( y.size() <= config::kMaxBignumSize ) { Pool_Bignum.Set(y); }
    }
}

template<> std::optional<component::ECC_Point> ExecutorBase<component::ECC_Point, operation::ECC_Point_Neg>::callModule(std::shared_ptr<Module> module, operation::ECC_Point_Neg& op) const {
    RETURN_IF_DISABLED(options.curves, op.curveType.Get());

    return module->OpECC_Point_Neg(op);
}

/* Specialization for operation::ECC_Point_Dbl */
template<> void ExecutorBase<component::ECC_Point, operation::ECC_Point_Dbl>::postprocess(std::shared_ptr<Module> module, operation::ECC_Point_Dbl& op, const ExecutorBase<component::ECC_Point, operation::ECC_Point_Dbl>::ResultPair& result) const {
    (void)module;

    if ( result.second != std::nullopt  ) {
        const auto curveID = op.curveType.Get();
        const auto x = result.second->first.ToTrimmedString();
        const auto y = result.second->second.ToTrimmedString();

        Pool_CurveECC_Point.Set({ curveID, x, y });

        if ( x.size() <= config::kMaxBignumSize ) { Pool_Bignum.Set(x); }
        if ( y.size() <= config::kMaxBignumSize ) { Pool_Bignum.Set(y); }
    }
}

template<> std::optional<component::ECC_Point> ExecutorBase<component::ECC_Point, operation::ECC_Point_Dbl>::callModule(std::shared_ptr<Module> module, operation::ECC_Point_Dbl& op) const {
    RETURN_IF_DISABLED(options.curves, op.curveType.Get());

    return module->OpECC_Point_Dbl(op);
}

/* Specialization for operation::DH_Derive */
template<> void ExecutorBase<component::Bignum, operation::DH_Derive>::postprocess(std::shared_ptr<Module> module, operation::DH_Derive& op, const ExecutorBase<component::Bignum, operation::DH_Derive>::ResultPair& result) const {
    (void)module;
    (void)op;
    (void)result;
}

template<> std::optional<component::Bignum> ExecutorBase<component::Bignum, operation::DH_Derive>::callModule(std::shared_ptr<Module> module, operation::DH_Derive& op) const {
    if ( op.prime.GetSize() > config::kMaxBignumSize ) return std::nullopt;
    if ( op.base.GetSize() > config::kMaxBignumSize ) return std::nullopt;
    if ( op.pub.GetSize() > config::kMaxBignumSize ) return std::nullopt;
    if ( op.priv.GetSize() > config::kMaxBignumSize ) return std::nullopt;

    return module->OpDH_Derive(op);
}

/* Specialization for operation::DH_GenerateKeyPair */
template<> void ExecutorBase<component::DH_KeyPair, operation::DH_GenerateKeyPair>::postprocess(std::shared_ptr<Module> module, operation::DH_GenerateKeyPair& op, const ExecutorBase<component::DH_KeyPair, operation::DH_GenerateKeyPair>::ResultPair& result) const {
    (void)result;
    (void)op;
    (void)module;

    if ( result.second != std::nullopt && (PRNG() % 4) == 0 ) {
        const auto priv = result.second->first.ToTrimmedString();
        const auto pub = result.second->second.ToTrimmedString();

        Pool_DH_PrivateKey.Set(priv);
        Pool_DH_PublicKey.Set(pub);
    }
}

template<> std::optional<component::DH_KeyPair> ExecutorBase<component::DH_KeyPair, operation::DH_GenerateKeyPair>::callModule(std::shared_ptr<Module> module, operation::DH_GenerateKeyPair& op) const {
    if ( op.prime.GetSize() > config::kMaxBignumSize ) return std::nullopt;
    if ( op.base.GetSize() > config::kMaxBignumSize ) return std::nullopt;

    return module->OpDH_GenerateKeyPair(op);
}

/* Specialization for operation::BignumCalc */
template<> void ExecutorBase<component::Bignum, operation::BignumCalc>::postprocess(std::shared_ptr<Module> module, operation::BignumCalc& op, const ExecutorBase<component::Bignum, operation::BignumCalc>::ResultPair& result) const {
    (void)module;
    (void)op;

    if ( result.second != std::nullopt  ) {
        const auto bignum = result.second->ToTrimmedString();

        if ( bignum.size() <= config::kMaxBignumSize ) {
            Pool_Bignum.Set(bignum);
            if ( op.calcOp.Is(CF_CALCOP("Prime()")) ) {
                Pool_Bignum_Primes.Set(bignum);
            }
        }
        if ( op.calcOp.Is(CF_CALCOP("IsPrime(A)")) ) {
            if ( bignum == "1" ) {
                Pool_Bignum_Primes.Set(op.bn0.ToTrimmedString());
            }
        }
    }
}

std::optional<component::Bignum> ExecutorBignumCalc::callModule(std::shared_ptr<Module> module, operation::BignumCalc& op) const {
    RETURN_IF_DISABLED(options.calcOps, op.calcOp.Get());

    /* Prevent timeouts */
    if ( op.bn0.GetSize() > config::kMaxBignumSize ) return std::nullopt;
    if ( op.bn1.GetSize() > config::kMaxBignumSize ) return std::nullopt;
    if ( op.bn2.GetSize() > config::kMaxBignumSize ) return std::nullopt;
    if ( op.bn3.GetSize() > config::kMaxBignumSize ) return std::nullopt;

    if ( op.modulo != std::nullopt && !module->SupportsModularBignumCalc() ) {
        return std::nullopt;
    }

    switch ( op.calcOp.Get() ) {
        case    CF_CALCOP("SetBit(A,B)"):
            /* Don't allow setting very high bit positions (risk of memory exhaustion) */
            if ( op.bn1.GetSize() > 4 ) {
                return std::nullopt;
            }
            break;
        case    CF_CALCOP("Exp(A,B)"):
            if ( op.bn0.GetSize() > 5 || op.bn1.GetSize() > 2 ) {
                return std::nullopt;
            }
            break;
        case    CF_CALCOP("ModLShift(A,B,C)"):
            if ( op.bn1.GetSize() > 4 ) {
                return std::nullopt;
            }
            break;
        case    CF_CALCOP("Exp2(A)"):
            if ( op.bn0.GetSize() > 4 ) {
                return std::nullopt;
            }
            break;
    }

    return module->OpBignumCalc(op);
}

/* Specialization for operation::BignumCalc_Fp2 */
template<> void ExecutorBase<component::Fp2, operation::BignumCalc_Fp2>::postprocess(std::shared_ptr<Module> module, operation::BignumCalc_Fp2& op, const ExecutorBase<component::Fp2, operation::BignumCalc_Fp2>::ResultPair& result) const {
    (void)module;
    (void)op;

    if ( result.second != std::nullopt  ) {
        const auto bignum_first = result.second->first.ToTrimmedString();
        const auto bignum_second = result.second->second.ToTrimmedString();

        if ( bignum_first.size() <= config::kMaxBignumSize ) {
            Pool_Bignum.Set(bignum_first);
        }
        if ( bignum_second.size() <= config::kMaxBignumSize ) {
            Pool_Bignum.Set(bignum_second);
        }
    }
}

std::optional<component::Fp2> ExecutorBignumCalc_Fp2::callModule(std::shared_ptr<Module> module, operation::BignumCalc_Fp2& op) const {
    RETURN_IF_DISABLED(options.calcOps, op.calcOp.Get());

    /* Prevent timeouts */
    if ( op.bn0.first.GetSize() > config::kMaxBignumSize ) return std::nullopt;
    if ( op.bn0.second.GetSize() > config::kMaxBignumSize ) return std::nullopt;
    if ( op.bn1.first.GetSize() > config::kMaxBignumSize ) return std::nullopt;
    if ( op.bn1.second.GetSize() > config::kMaxBignumSize ) return std::nullopt;
    if ( op.bn2.first.GetSize() > config::kMaxBignumSize ) return std::nullopt;
    if ( op.bn2.second.GetSize() > config::kMaxBignumSize ) return std::nullopt;
    if ( op.bn3.first.GetSize() > config::kMaxBignumSize ) return std::nullopt;
    if ( op.bn3.second.GetSize() > config::kMaxBignumSize ) return std::nullopt;

    if ( op.modulo != std::nullopt && !module->SupportsModularBignumCalc() ) {
        return std::nullopt;
    }

    return module->OpBignumCalc_Fp2(op);
}

/* Specialization for operation::BignumCalc_Fp12 */
template<> void ExecutorBase<component::Fp12, operation::BignumCalc_Fp12>::postprocess(std::shared_ptr<Module> module, operation::BignumCalc_Fp12& op, const ExecutorBase<component::Fp12, operation::BignumCalc_Fp12>::ResultPair& result) const {
    (void)module;
    (void)op;

    if ( result.second != std::nullopt  ) {
        Pool_Fp12.Set({
                result.second->bn1.ToTrimmedString(),
                result.second->bn2.ToTrimmedString(),
                result.second->bn3.ToTrimmedString(),
                result.second->bn4.ToTrimmedString(),
                result.second->bn5.ToTrimmedString(),
                result.second->bn6.ToTrimmedString(),
                result.second->bn7.ToTrimmedString(),
                result.second->bn8.ToTrimmedString(),
                result.second->bn9.ToTrimmedString(),
                result.second->bn10.ToTrimmedString(),
                result.second->bn11.ToTrimmedString(),
                result.second->bn12.ToTrimmedString()
        });
        /* TODO */
#if 0
        const auto bignum_first = result.second->first.ToTrimmedString();
        const auto bignum_second = result.second->second.ToTrimmedString();

        if ( bignum_first.size() <= config::kMaxBignumSize ) {
            Pool_Bignum.Set(bignum_first);
        }
        if ( bignum_second.size() <= config::kMaxBignumSize ) {
            Pool_Bignum.Set(bignum_second);
        }
#endif
    }
}

std::optional<component::Fp12> ExecutorBignumCalc_Fp12::callModule(std::shared_ptr<Module> module, operation::BignumCalc_Fp12& op) const {
    RETURN_IF_DISABLED(options.calcOps, op.calcOp.Get());

    /* Prevent timeouts */
    if ( op.bn0.bn1.GetSize() > config::kMaxBignumSize ) return std::nullopt;
    if ( op.bn0.bn2.GetSize() > config::kMaxBignumSize ) return std::nullopt;
    if ( op.bn0.bn3.GetSize() > config::kMaxBignumSize ) return std::nullopt;
    if ( op.bn0.bn4.GetSize() > config::kMaxBignumSize ) return std::nullopt;
    if ( op.bn0.bn5.GetSize() > config::kMaxBignumSize ) return std::nullopt;
    if ( op.bn0.bn6.GetSize() > config::kMaxBignumSize ) return std::nullopt;
    if ( op.bn0.bn7.GetSize() > config::kMaxBignumSize ) return std::nullopt;
    if ( op.bn0.bn8.GetSize() > config::kMaxBignumSize ) return std::nullopt;
    if ( op.bn0.bn9.GetSize() > config::kMaxBignumSize ) return std::nullopt;
    if ( op.bn0.bn10.GetSize() > config::kMaxBignumSize ) return std::nullopt;
    if ( op.bn0.bn11.GetSize() > config::kMaxBignumSize ) return std::nullopt;
    if ( op.bn0.bn12.GetSize() > config::kMaxBignumSize ) return std::nullopt;

    if ( op.bn1.bn1.GetSize() > config::kMaxBignumSize ) return std::nullopt;
    if ( op.bn1.bn2.GetSize() > config::kMaxBignumSize ) return std::nullopt;
    if ( op.bn1.bn3.GetSize() > config::kMaxBignumSize ) return std::nullopt;
    if ( op.bn1.bn4.GetSize() > config::kMaxBignumSize ) return std::nullopt;
    if ( op.bn1.bn5.GetSize() > config::kMaxBignumSize ) return std::nullopt;
    if ( op.bn1.bn6.GetSize() > config::kMaxBignumSize ) return std::nullopt;
    if ( op.bn1.bn7.GetSize() > config::kMaxBignumSize ) return std::nullopt;
    if ( op.bn1.bn8.GetSize() > config::kMaxBignumSize ) return std::nullopt;
    if ( op.bn1.bn9.GetSize() > config::kMaxBignumSize ) return std::nullopt;
    if ( op.bn1.bn10.GetSize() > config::kMaxBignumSize ) return std::nullopt;
    if ( op.bn1.bn11.GetSize() > config::kMaxBignumSize ) return std::nullopt;
    if ( op.bn1.bn12.GetSize() > config::kMaxBignumSize ) return std::nullopt;

    if ( op.bn2.bn1.GetSize() > config::kMaxBignumSize ) return std::nullopt;
    if ( op.bn2.bn2.GetSize() > config::kMaxBignumSize ) return std::nullopt;
    if ( op.bn2.bn3.GetSize() > config::kMaxBignumSize ) return std::nullopt;
    if ( op.bn2.bn4.GetSize() > config::kMaxBignumSize ) return std::nullopt;
    if ( op.bn2.bn5.GetSize() > config::kMaxBignumSize ) return std::nullopt;
    if ( op.bn2.bn6.GetSize() > config::kMaxBignumSize ) return std::nullopt;
    if ( op.bn2.bn7.GetSize() > config::kMaxBignumSize ) return std::nullopt;
    if ( op.bn2.bn8.GetSize() > config::kMaxBignumSize ) return std::nullopt;
    if ( op.bn2.bn9.GetSize() > config::kMaxBignumSize ) return std::nullopt;
    if ( op.bn2.bn10.GetSize() > config::kMaxBignumSize ) return std::nullopt;
    if ( op.bn2.bn11.GetSize() > config::kMaxBignumSize ) return std::nullopt;
    if ( op.bn2.bn12.GetSize() > config::kMaxBignumSize ) return std::nullopt;

    if ( op.bn3.bn1.GetSize() > config::kMaxBignumSize ) return std::nullopt;
    if ( op.bn3.bn2.GetSize() > config::kMaxBignumSize ) return std::nullopt;
    if ( op.bn3.bn3.GetSize() > config::kMaxBignumSize ) return std::nullopt;
    if ( op.bn3.bn4.GetSize() > config::kMaxBignumSize ) return std::nullopt;
    if ( op.bn3.bn5.GetSize() > config::kMaxBignumSize ) return std::nullopt;
    if ( op.bn3.bn6.GetSize() > config::kMaxBignumSize ) return std::nullopt;
    if ( op.bn3.bn7.GetSize() > config::kMaxBignumSize ) return std::nullopt;
    if ( op.bn3.bn8.GetSize() > config::kMaxBignumSize ) return std::nullopt;
    if ( op.bn3.bn9.GetSize() > config::kMaxBignumSize ) return std::nullopt;
    if ( op.bn3.bn10.GetSize() > config::kMaxBignumSize ) return std::nullopt;
    if ( op.bn3.bn11.GetSize() > config::kMaxBignumSize ) return std::nullopt;
    if ( op.bn3.bn12.GetSize() > config::kMaxBignumSize ) return std::nullopt;

    if ( op.modulo != std::nullopt && !module->SupportsModularBignumCalc() ) {
        return std::nullopt;
    }

    return module->OpBignumCalc_Fp12(op);
}

/* Specialization for operation::BLS_PrivateToPublic */
template<> void ExecutorBase<component::BLS_PublicKey, operation::BLS_PrivateToPublic>::postprocess(std::shared_ptr<Module> module, operation::BLS_PrivateToPublic& op, const ExecutorBase<component::BLS_PublicKey, operation::BLS_PrivateToPublic>::ResultPair& result) const {
    (void)module;

    if ( result.second != std::nullopt  ) {
        const auto curveID = op.curveType.Get();
        const auto g1_x = result.second->first.ToTrimmedString();
        const auto g1_y = result.second->second.ToTrimmedString();

        G1AddToPool(curveID, g1_x, g1_y);

        if ( g1_x.size() <= config::kMaxBignumSize ) { Pool_Bignum.Set(g1_x); }
        if ( g1_y.size() <= config::kMaxBignumSize ) { Pool_Bignum.Set(g1_y); }
    }
}

template<> std::optional<component::BLS_PublicKey> ExecutorBase<component::BLS_PublicKey, operation::BLS_PrivateToPublic>::callModule(std::shared_ptr<Module> module, operation::BLS_PrivateToPublic& op) const {
    const size_t size = op.priv.ToTrimmedString().size();

    if ( size == 0 || size > 4096 ) {
        return std::nullopt;
    }

    return module->OpBLS_PrivateToPublic(op);
}

/* Specialization for operation::BLS_PrivateToPublic_G2 */
template<> void ExecutorBase<component::G2, operation::BLS_PrivateToPublic_G2>::postprocess(std::shared_ptr<Module> module, operation::BLS_PrivateToPublic_G2& op, const ExecutorBase<component::G2, operation::BLS_PrivateToPublic_G2>::ResultPair& result) const {
    (void)module;
    if ( result.second != std::nullopt  ) {
        const auto curveID = op.curveType.Get();
        const auto g2_v = result.second->first.first.ToTrimmedString();
        const auto g2_w = result.second->first.second.ToTrimmedString();
        const auto g2_x = result.second->second.first.ToTrimmedString();
        const auto g2_y = result.second->second.second.ToTrimmedString();

        G2AddToPool(curveID, g2_v, g2_w, g2_x, g2_y);

        if ( g2_v.size() <= config::kMaxBignumSize ) { Pool_Bignum.Set(g2_v); }
        if ( g2_w.size() <= config::kMaxBignumSize ) { Pool_Bignum.Set(g2_w); }
        if ( g2_x.size() <= config::kMaxBignumSize ) { Pool_Bignum.Set(g2_x); }
        if ( g2_y.size() <= config::kMaxBignumSize ) { Pool_Bignum.Set(g2_y); }
    }
}

template<> std::optional<component::G2> ExecutorBase<component::G2, operation::BLS_PrivateToPublic_G2>::callModule(std::shared_ptr<Module> module, operation::BLS_PrivateToPublic_G2& op) const {
    const size_t size = op.priv.ToTrimmedString().size();

    if ( size == 0 || size > 4096 ) {
        return std::nullopt;
    }

    return module->OpBLS_PrivateToPublic_G2(op);
}

/* Specialization for operation::BLS_Sign */
template<> void ExecutorBase<component::BLS_Signature, operation::BLS_Sign>::postprocess(std::shared_ptr<Module> module, operation::BLS_Sign& op, const ExecutorBase<component::BLS_Signature, operation::BLS_Sign>::ResultPair& result) const {
    (void)module;

    if ( result.second != std::nullopt  ) {
        const auto curveID = op.curveType.Get();
        const auto point_v = op.hashOrPoint ? op.point.first.first.ToTrimmedString() : "";
        const auto point_w = op.hashOrPoint ? op.point.first.second.ToTrimmedString() : "";
        const auto point_x = op.hashOrPoint ? op.point.second.first.ToTrimmedString() : "";
        const auto point_y = op.hashOrPoint ? op.point.second.second.ToTrimmedString() : "";
        const auto cleartext = op.hashOrPoint ? op.cleartext.ToHex() : "";
        const auto dest = op.dest.ToHex();
        const auto aug = op.aug.ToHex();
        const auto pub_x = result.second->pub.first.ToTrimmedString();
        const auto pub_y = result.second->pub.second.ToTrimmedString();
        const auto sig_v = result.second->signature.first.first.ToTrimmedString();
        const auto sig_w = result.second->signature.first.second.ToTrimmedString();
        const auto sig_x = result.second->signature.second.first.ToTrimmedString();
        const auto sig_y = result.second->signature.second.second.ToTrimmedString();

        G1AddToPool(curveID, pub_x, pub_y);
        G2AddToPool(curveID, sig_v, sig_w, sig_x, sig_y);
        Pool_CurveBLSSignature.Set({ curveID, op.hashOrPoint, point_v, point_w, point_x, point_y, cleartext, dest, aug, pub_x, pub_y, sig_v, sig_w, sig_x, sig_y});

        if ( pub_x.size() <= config::kMaxBignumSize ) { Pool_Bignum.Set(pub_x); }
        if ( pub_y.size() <= config::kMaxBignumSize ) { Pool_Bignum.Set(pub_y); }
        if ( sig_v.size() <= config::kMaxBignumSize ) { Pool_Bignum.Set(sig_v); }
        if ( sig_w.size() <= config::kMaxBignumSize ) { Pool_Bignum.Set(sig_w); }
        if ( sig_x.size() <= config::kMaxBignumSize ) { Pool_Bignum.Set(sig_x); }
        if ( sig_y.size() <= config::kMaxBignumSize ) { Pool_Bignum.Set(sig_y); }
    }
}

template<> std::optional<component::BLS_Signature> ExecutorBase<component::BLS_Signature, operation::BLS_Sign>::callModule(std::shared_ptr<Module> module, operation::BLS_Sign& op) const {
    const size_t size = op.priv.ToTrimmedString().size();

    if ( size == 0 || size > 4096 ) {
        return std::nullopt;
    }

    return module->OpBLS_Sign(op);
}

/* Specialization for operation::BLS_Verify */
template<> void ExecutorBase<bool, operation::BLS_Verify>::postprocess(std::shared_ptr<Module> module, operation::BLS_Verify& op, const ExecutorBase<bool, operation::BLS_Verify>::ResultPair& result) const {
    (void)module;
    (void)op;
    (void)result;
}

template<> std::optional<bool> ExecutorBase<bool, operation::BLS_Verify>::callModule(std::shared_ptr<Module> module, operation::BLS_Verify& op) const {
#if 0
    const std::vector<size_t> sizes = {
        op.pub.first.ToTrimmedString().size(),
        op.pub.second.ToTrimmedString().size(),
        op.signature.first.ToTrimmedString().size(),
        op.signature.second.ToTrimmedString().size(),
    };

    for (const auto& size : sizes) {
        if ( size == 0 || size > 4096 ) {
            return std::nullopt;
        }
    }
#endif

    return module->OpBLS_Verify(op);
}

/* Specialization for operation::BLS_BatchSign */
template<> void ExecutorBase<component::BLS_BatchSignature, operation::BLS_BatchSign>::postprocess(std::shared_ptr<Module> module, operation::BLS_BatchSign& op, const ExecutorBase<component::BLS_BatchSignature, operation::BLS_BatchSign>::ResultPair& result) const {
    (void)module;
    (void)op;

    if ( result.second != std::nullopt  ) {
        std::vector< std::pair<BLS_BatchSignature_::G1, BLS_BatchSignature_::G2> > msgpub;
        for (const auto& mp : result.second->msgpub) {
            msgpub.push_back(
                    std::pair<BLS_BatchSignature_::G1, BLS_BatchSignature_::G2>{
                        {
                            mp.first.first.ToTrimmedString(),
                            mp.first.second.ToTrimmedString()
                        },
                        {
                            mp.second.first.first.ToTrimmedString(),
                            mp.second.first.second.ToTrimmedString(),
                            mp.second.second.first.ToTrimmedString(),
                            mp.second.second.second.ToTrimmedString()
                        }
                    }
            );
            G1AddToPool(CF_ECC_CURVE("BLS12_381"), mp.first.first.ToTrimmedString(), mp.first.second.ToTrimmedString());
            Pool_CurveBLSG2.Set({
                    CF_ECC_CURVE("BLS12_381"),
                    mp.second.first.first.ToTrimmedString(),
                    mp.second.first.second.ToTrimmedString(),
                    mp.second.second.first.ToTrimmedString(),
                    mp.second.second.second.ToTrimmedString()
            });
        }
        Pool_BLS_BatchSignature.Set({msgpub});
    }
}

template<> std::optional<component::BLS_BatchSignature> ExecutorBase<component::BLS_BatchSignature, operation::BLS_BatchSign>::callModule(std::shared_ptr<Module> module, operation::BLS_BatchSign& op) const {
    return module->OpBLS_BatchSign(op);
}

/* Specialization for operation::BLS_BatchVerify */
template<> void ExecutorBase<bool, operation::BLS_BatchVerify>::postprocess(std::shared_ptr<Module> module, operation::BLS_BatchVerify& op, const ExecutorBase<bool, operation::BLS_BatchVerify>::ResultPair& result) const {
    (void)module;
    (void)op;
    (void)result;
}

template<> std::optional<bool> ExecutorBase<bool, operation::BLS_BatchVerify>::callModule(std::shared_ptr<Module> module, operation::BLS_BatchVerify& op) const {
    return module->OpBLS_BatchVerify(op);
}

/* Specialization for operation::BLS_Aggregate_G1 */
template<> void ExecutorBase<component::G1, operation::BLS_Aggregate_G1>::postprocess(std::shared_ptr<Module> module, operation::BLS_Aggregate_G1& op, const ExecutorBase<component::G1, operation::BLS_Aggregate_G1>::ResultPair& result) const {
    (void)module;
    (void)op;
    (void)result;
}

template<> std::optional<component::G1> ExecutorBase<component::G1, operation::BLS_Aggregate_G1>::callModule(std::shared_ptr<Module> module, operation::BLS_Aggregate_G1& op) const {
    return module->OpBLS_Aggregate_G1(op);
}

/* Specialization for operation::BLS_Aggregate_G2 */
template<> void ExecutorBase<component::G2, operation::BLS_Aggregate_G2>::postprocess(std::shared_ptr<Module> module, operation::BLS_Aggregate_G2& op, const ExecutorBase<component::G2, operation::BLS_Aggregate_G2>::ResultPair& result) const {
    (void)module;
    (void)op;
    (void)result;
}

template<> std::optional<component::G2> ExecutorBase<component::G2, operation::BLS_Aggregate_G2>::callModule(std::shared_ptr<Module> module, operation::BLS_Aggregate_G2& op) const {
    return module->OpBLS_Aggregate_G2(op);
}

/* Specialization for operation::BLS_Pairing */
template<> void ExecutorBase<component::Fp12, operation::BLS_Pairing>::postprocess(std::shared_ptr<Module> module, operation::BLS_Pairing& op, const ExecutorBase<component::Fp12, operation::BLS_Pairing>::ResultPair& result) const {
    (void)module;
    (void)op;

    if ( result.second != std::nullopt  ) {
        Pool_Fp12.Set({
                result.second->bn1.ToTrimmedString(),
                result.second->bn2.ToTrimmedString(),
                result.second->bn3.ToTrimmedString(),
                result.second->bn4.ToTrimmedString(),
                result.second->bn5.ToTrimmedString(),
                result.second->bn6.ToTrimmedString(),
                result.second->bn7.ToTrimmedString(),
                result.second->bn8.ToTrimmedString(),
                result.second->bn9.ToTrimmedString(),
                result.second->bn10.ToTrimmedString(),
                result.second->bn11.ToTrimmedString(),
                result.second->bn12.ToTrimmedString()
        });
    }
}

template<> std::optional<component::Fp12> ExecutorBase<component::Fp12, operation::BLS_Pairing>::callModule(std::shared_ptr<Module> module, operation::BLS_Pairing& op) const {
    return module->OpBLS_Pairing(op);
}

/* Specialization for operation::BLS_MillerLoop */
template<> void ExecutorBase<component::Fp12, operation::BLS_MillerLoop>::postprocess(std::shared_ptr<Module> module, operation::BLS_MillerLoop& op, const ExecutorBase<component::Fp12, operation::BLS_MillerLoop>::ResultPair& result) const {
    (void)module;
    (void)op;

    if ( result.second != std::nullopt  ) {
        Pool_Fp12.Set({
                result.second->bn1.ToTrimmedString(),
                result.second->bn2.ToTrimmedString(),
                result.second->bn3.ToTrimmedString(),
                result.second->bn4.ToTrimmedString(),
                result.second->bn5.ToTrimmedString(),
                result.second->bn6.ToTrimmedString(),
                result.second->bn7.ToTrimmedString(),
                result.second->bn8.ToTrimmedString(),
                result.second->bn9.ToTrimmedString(),
                result.second->bn10.ToTrimmedString(),
                result.second->bn11.ToTrimmedString(),
                result.second->bn12.ToTrimmedString()
        });
    }
}

template<> std::optional<component::Fp12> ExecutorBase<component::Fp12, operation::BLS_MillerLoop>::callModule(std::shared_ptr<Module> module, operation::BLS_MillerLoop& op) const {
    return module->OpBLS_MillerLoop(op);
}

/* Specialization for operation::BLS_FinalExp */
template<> void ExecutorBase<component::Fp12, operation::BLS_FinalExp>::postprocess(std::shared_ptr<Module> module, operation::BLS_FinalExp& op, const ExecutorBase<component::Fp12, operation::BLS_FinalExp>::ResultPair& result) const {
    (void)module;
    (void)op;

    if ( result.second != std::nullopt  ) {
        Pool_Fp12.Set({
                result.second->bn1.ToTrimmedString(),
                result.second->bn2.ToTrimmedString(),
                result.second->bn3.ToTrimmedString(),
                result.second->bn4.ToTrimmedString(),
                result.second->bn5.ToTrimmedString(),
                result.second->bn6.ToTrimmedString(),
                result.second->bn7.ToTrimmedString(),
                result.second->bn8.ToTrimmedString(),
                result.second->bn9.ToTrimmedString(),
                result.second->bn10.ToTrimmedString(),
                result.second->bn11.ToTrimmedString(),
                result.second->bn12.ToTrimmedString()
        });
    }
}

template<> std::optional<component::Fp12> ExecutorBase<component::Fp12, operation::BLS_FinalExp>::callModule(std::shared_ptr<Module> module, operation::BLS_FinalExp& op) const {
    return module->OpBLS_FinalExp(op);
}

/* Specialization for operation::BLS_HashToG1 */
template<> void ExecutorBase<component::G1, operation::BLS_HashToG1>::postprocess(std::shared_ptr<Module> module, operation::BLS_HashToG1& op, const ExecutorBase<component::G1, operation::BLS_HashToG1>::ResultPair& result) const {
    (void)module;

    if ( result.second != std::nullopt  ) {
        const auto curveID = op.curveType.Get();
        const auto g1_x = result.second->first.ToTrimmedString();
        const auto g1_y = result.second->second.ToTrimmedString();

        G1AddToPool(curveID, g1_x, g1_y);

        if ( g1_x.size() <= config::kMaxBignumSize ) { Pool_Bignum.Set(g1_x); }
        if ( g1_y.size() <= config::kMaxBignumSize ) { Pool_Bignum.Set(g1_y); }
    }
}

template<> std::optional<component::G1> ExecutorBase<component::G1, operation::BLS_HashToG1>::callModule(std::shared_ptr<Module> module, operation::BLS_HashToG1& op) const {
    return module->OpBLS_HashToG1(op);
}

/* Specialization for operation::BLS_MapToG1 */
template<> void ExecutorBase<component::G1, operation::BLS_MapToG1>::postprocess(std::shared_ptr<Module> module, operation::BLS_MapToG1& op, const ExecutorBase<component::G1, operation::BLS_MapToG1>::ResultPair& result) const {
    (void)module;

    if ( result.second != std::nullopt  ) {
        const auto curveID = op.curveType.Get();
        const auto g1_x = result.second->first.ToTrimmedString();
        const auto g1_y = result.second->second.ToTrimmedString();

        G1AddToPool(curveID, g1_x, g1_y);

        if ( g1_x.size() <= config::kMaxBignumSize ) { Pool_Bignum.Set(g1_x); }
        if ( g1_y.size() <= config::kMaxBignumSize ) { Pool_Bignum.Set(g1_y); }
    }
}

template<> std::optional<component::G1> ExecutorBase<component::G1, operation::BLS_MapToG1>::callModule(std::shared_ptr<Module> module, operation::BLS_MapToG1& op) const {
    return module->OpBLS_MapToG1(op);
}

/* Specialization for operation::BLS_MapToG2 */
template<> void ExecutorBase<component::G2, operation::BLS_MapToG2>::postprocess(std::shared_ptr<Module> module, operation::BLS_MapToG2& op, const ExecutorBase<component::G2, operation::BLS_MapToG2>::ResultPair& result) const {
    (void)module;

    if ( result.second != std::nullopt  ) {
        const auto curveID = op.curveType.Get();
        const auto g2_v = result.second->first.first.ToTrimmedString();
        const auto g2_w = result.second->first.second.ToTrimmedString();
        const auto g2_x = result.second->second.first.ToTrimmedString();
        const auto g2_y = result.second->second.second.ToTrimmedString();

        G2AddToPool(curveID, g2_v, g2_w, g2_x, g2_y);

        if ( g2_v.size() <= config::kMaxBignumSize ) { Pool_Bignum.Set(g2_v); }
        if ( g2_w.size() <= config::kMaxBignumSize ) { Pool_Bignum.Set(g2_w); }
        if ( g2_x.size() <= config::kMaxBignumSize ) { Pool_Bignum.Set(g2_x); }
        if ( g2_y.size() <= config::kMaxBignumSize ) { Pool_Bignum.Set(g2_y); }
    }
}

template<> std::optional<component::G2> ExecutorBase<component::G2, operation::BLS_MapToG2>::callModule(std::shared_ptr<Module> module, operation::BLS_MapToG2& op) const {
    return module->OpBLS_MapToG2(op);
}

/* Specialization for operation::BLS_IsG1OnCurve */
template<> void ExecutorBase<bool, operation::BLS_IsG1OnCurve>::postprocess(std::shared_ptr<Module> module, operation::BLS_IsG1OnCurve& op, const ExecutorBase<bool, operation::BLS_IsG1OnCurve>::ResultPair& result) const {
    (void)module;
    (void)op;
    (void)result;
}

template<> std::optional<bool> ExecutorBase<bool, operation::BLS_IsG1OnCurve>::callModule(std::shared_ptr<Module> module, operation::BLS_IsG1OnCurve& op) const {
    if ( op.g1.first.GetSize() > config::kMaxBignumSize ) return std::nullopt;
    if ( op.g1.second.GetSize() > config::kMaxBignumSize ) return std::nullopt;

    return module->OpBLS_IsG1OnCurve(op);
}

/* Specialization for operation::BLS_IsG2OnCurve */
template<> void ExecutorBase<bool, operation::BLS_IsG2OnCurve>::postprocess(std::shared_ptr<Module> module, operation::BLS_IsG2OnCurve& op, const ExecutorBase<bool, operation::BLS_IsG2OnCurve>::ResultPair& result) const {
    (void)module;
    (void)op;
    (void)result;
}

template<> std::optional<bool> ExecutorBase<bool, operation::BLS_IsG2OnCurve>::callModule(std::shared_ptr<Module> module, operation::BLS_IsG2OnCurve& op) const {
    if ( op.g2.first.first.GetSize() > config::kMaxBignumSize ) return std::nullopt;
    if ( op.g2.first.second.GetSize() > config::kMaxBignumSize ) return std::nullopt;
    if ( op.g2.second.first.GetSize() > config::kMaxBignumSize ) return std::nullopt;
    if ( op.g2.second.second.GetSize() > config::kMaxBignumSize ) return std::nullopt;

    return module->OpBLS_IsG2OnCurve(op);
}

/* Specialization for operation::BLS_GenerateKeyPair */
template<> void ExecutorBase<component::BLS_KeyPair, operation::BLS_GenerateKeyPair>::postprocess(std::shared_ptr<Module> module, operation::BLS_GenerateKeyPair& op, const ExecutorBase<component::BLS_KeyPair, operation::BLS_GenerateKeyPair>::ResultPair& result) const {
    (void)module;

    if ( result.second != std::nullopt  ) {
        const auto curveID = op.curveType.Get();
        const auto priv = result.second->priv.ToTrimmedString();
        const auto g1_x = result.second->pub.first.ToTrimmedString();
        const auto g1_y = result.second->pub.second.ToTrimmedString();

        G1AddToPool(curveID, g1_x, g1_y);

        if ( priv.size() <= config::kMaxBignumSize ) { Pool_Bignum.Set(priv); }
        if ( g1_x.size() <= config::kMaxBignumSize ) { Pool_Bignum.Set(g1_x); }
        if ( g1_y.size() <= config::kMaxBignumSize ) { Pool_Bignum.Set(g1_y); }
    }
}

template<> std::optional<component::BLS_KeyPair> ExecutorBase<component::BLS_KeyPair, operation::BLS_GenerateKeyPair>::callModule(std::shared_ptr<Module> module, operation::BLS_GenerateKeyPair& op) const {
    return module->OpBLS_GenerateKeyPair(op);
}

/* Specialization for operation::BLS_Decompress_G1 */
template<> void ExecutorBase<component::G1, operation::BLS_Decompress_G1>::postprocess(std::shared_ptr<Module> module, operation::BLS_Decompress_G1& op, const ExecutorBase<component::G1, operation::BLS_Decompress_G1>::ResultPair& result) const {
    (void)module;

    if ( result.second != std::nullopt  ) {
        const auto curveID = op.curveType.Get();
        const auto g1_x = result.second->first.ToTrimmedString();
        const auto g1_y = result.second->second.ToTrimmedString();

        G1AddToPool(curveID, g1_x, g1_y);

        if ( g1_x.size() <= config::kMaxBignumSize ) { Pool_Bignum.Set(g1_x); }
        if ( g1_y.size() <= config::kMaxBignumSize ) { Pool_Bignum.Set(g1_y); }
    }
}

template<> std::optional<component::G1> ExecutorBase<component::G1, operation::BLS_Decompress_G1>::callModule(std::shared_ptr<Module> module, operation::BLS_Decompress_G1& op) const {
    return module->OpBLS_Decompress_G1(op);
}

/* Specialization for operation::BLS_Compress_G1 */
template<> void ExecutorBase<component::Bignum, operation::BLS_Compress_G1>::postprocess(std::shared_ptr<Module> module, operation::BLS_Compress_G1& op, const ExecutorBase<component::Bignum, operation::BLS_Compress_G1>::ResultPair& result) const {
    (void)module;

    if ( result.second != std::nullopt  ) {
        const auto compressed = result.second->ToTrimmedString();

        if ( compressed.size() <= config::kMaxBignumSize ) { Pool_Bignum.Set(compressed); }
    }
}

template<> std::optional<component::Bignum> ExecutorBase<component::Bignum, operation::BLS_Compress_G1>::callModule(std::shared_ptr<Module> module, operation::BLS_Compress_G1& op) const {
    return module->OpBLS_Compress_G1(op);
}

/* Specialization for operation::BLS_Decompress_G2 */
template<> void ExecutorBase<component::G2, operation::BLS_Decompress_G2>::postprocess(std::shared_ptr<Module> module, operation::BLS_Decompress_G2& op, const ExecutorBase<component::G2, operation::BLS_Decompress_G2>::ResultPair& result) const {
    (void)module;

    if ( result.second != std::nullopt  ) {
        const auto curveID = op.curveType.Get();
        const auto g2_v = result.second->first.first.ToTrimmedString();
        const auto g2_w = result.second->first.second.ToTrimmedString();
        const auto g2_x = result.second->second.first.ToTrimmedString();
        const auto g2_y = result.second->second.second.ToTrimmedString();

        G2AddToPool(curveID, g2_v, g2_w, g2_x, g2_y);

        if ( g2_v.size() <= config::kMaxBignumSize ) { Pool_Bignum.Set(g2_v); }
        if ( g2_w.size() <= config::kMaxBignumSize ) { Pool_Bignum.Set(g2_w); }
        if ( g2_x.size() <= config::kMaxBignumSize ) { Pool_Bignum.Set(g2_x); }
        if ( g2_y.size() <= config::kMaxBignumSize ) { Pool_Bignum.Set(g2_y); }
    }
}

template<> std::optional<component::G2> ExecutorBase<component::G2, operation::BLS_Decompress_G2>::callModule(std::shared_ptr<Module> module, operation::BLS_Decompress_G2& op) const {
    return module->OpBLS_Decompress_G2(op);
}

/* Specialization for operation::BLS_Compress_G2 */
template<> void ExecutorBase<component::G1, operation::BLS_Compress_G2>::postprocess(std::shared_ptr<Module> module, operation::BLS_Compress_G2& op, const ExecutorBase<component::G1, operation::BLS_Compress_G2>::ResultPair& result) const {
    (void)module;

    if ( result.second != std::nullopt  ) {
        const auto curveID = op.curveType.Get();
        const auto g1_x = result.second->first.ToTrimmedString();
        const auto g1_y = result.second->second.ToTrimmedString();

        G1AddToPool(curveID, g1_x, g1_y);

        if ( g1_x.size() <= config::kMaxBignumSize ) { Pool_Bignum.Set(g1_x); }
        if ( g1_y.size() <= config::kMaxBignumSize ) { Pool_Bignum.Set(g1_y); }
    }
}

template<> std::optional<component::G1> ExecutorBase<component::G1, operation::BLS_Compress_G2>::callModule(std::shared_ptr<Module> module, operation::BLS_Compress_G2& op) const {
    return module->OpBLS_Compress_G2(op);
}

/* Specialization for operation::BLS_G1_Add */
template<> void ExecutorBase<component::G1, operation::BLS_G1_Add>::postprocess(std::shared_ptr<Module> module, operation::BLS_G1_Add& op, const ExecutorBase<component::G1, operation::BLS_G1_Add>::ResultPair& result) const {
    (void)module;

    if ( result.second != std::nullopt  ) {
        const auto curveID = op.curveType.Get();
        const auto g1_x = result.second->first.ToTrimmedString();
        const auto g1_y = result.second->second.ToTrimmedString();

        G1AddToPool(curveID, g1_x, g1_y);

        if ( g1_x.size() <= config::kMaxBignumSize ) { Pool_Bignum.Set(g1_x); }
        if ( g1_y.size() <= config::kMaxBignumSize ) { Pool_Bignum.Set(g1_y); }
    }
}

template<> std::optional<component::G1> ExecutorBase<component::G1, operation::BLS_G1_Add>::callModule(std::shared_ptr<Module> module, operation::BLS_G1_Add& op) const {
    if ( op.a.first.GetSize() > config::kMaxBignumSize ) return std::nullopt;
    if ( op.a.second.GetSize() > config::kMaxBignumSize ) return std::nullopt;
    if ( op.b.first.GetSize() > config::kMaxBignumSize ) return std::nullopt;
    if ( op.b.second.GetSize() > config::kMaxBignumSize ) return std::nullopt;

    return module->OpBLS_G1_Add(op);
}

/* Specialization for operation::BLS_G1_Mul */
template<> void ExecutorBase<component::G1, operation::BLS_G1_Mul>::postprocess(std::shared_ptr<Module> module, operation::BLS_G1_Mul& op, const ExecutorBase<component::G1, operation::BLS_G1_Mul>::ResultPair& result) const {
    (void)module;

    if ( result.second != std::nullopt  ) {
        const auto curveID = op.curveType.Get();
        const auto g1_x = result.second->first.ToTrimmedString();
        const auto g1_y = result.second->second.ToTrimmedString();

        G1AddToPool(curveID, g1_x, g1_y);

        if ( g1_x.size() <= config::kMaxBignumSize ) { Pool_Bignum.Set(g1_x); }
        if ( g1_y.size() <= config::kMaxBignumSize ) { Pool_Bignum.Set(g1_y); }
    }
}

template<> std::optional<component::G1> ExecutorBase<component::G1, operation::BLS_G1_Mul>::callModule(std::shared_ptr<Module> module, operation::BLS_G1_Mul& op) const {
    if ( op.a.first.GetSize() > config::kMaxBignumSize ) return std::nullopt;
    if ( op.a.second.GetSize() > config::kMaxBignumSize ) return std::nullopt;
    if ( op.b.GetSize() > config::kMaxBignumSize ) return std::nullopt;

    return module->OpBLS_G1_Mul(op);
}

/* Specialization for operation::BLS_G1_IsEq */
template<> void ExecutorBase<bool, operation::BLS_G1_IsEq>::postprocess(std::shared_ptr<Module> module, operation::BLS_G1_IsEq& op, const ExecutorBase<bool, operation::BLS_G1_IsEq>::ResultPair& result) const {
    (void)module;
    (void)op;
    (void)result;
}

template<> std::optional<bool> ExecutorBase<bool, operation::BLS_G1_IsEq>::callModule(std::shared_ptr<Module> module, operation::BLS_G1_IsEq& op) const {
    if ( op.a.first.GetSize() > config::kMaxBignumSize ) return std::nullopt;
    if ( op.a.second.GetSize() > config::kMaxBignumSize ) return std::nullopt;
    if ( op.b.first.GetSize() > config::kMaxBignumSize ) return std::nullopt;
    if ( op.b.second.GetSize() > config::kMaxBignumSize ) return std::nullopt;

    return module->OpBLS_G1_IsEq(op);
}

/* Specialization for operation::BLS_G1_Neg */
template<> void ExecutorBase<component::G1, operation::BLS_G1_Neg>::postprocess(std::shared_ptr<Module> module, operation::BLS_G1_Neg& op, const ExecutorBase<component::G1, operation::BLS_G1_Neg>::ResultPair& result) const {
    (void)module;

    if ( result.second != std::nullopt  ) {
        const auto curveID = op.curveType.Get();
        const auto g1_x = result.second->first.ToTrimmedString();
        const auto g1_y = result.second->second.ToTrimmedString();

        G1AddToPool(curveID, g1_x, g1_y);

        if ( g1_x.size() <= config::kMaxBignumSize ) { Pool_Bignum.Set(g1_x); }
        if ( g1_y.size() <= config::kMaxBignumSize ) { Pool_Bignum.Set(g1_y); }
    }
}

template<> std::optional<component::G1> ExecutorBase<component::G1, operation::BLS_G1_Neg>::callModule(std::shared_ptr<Module> module, operation::BLS_G1_Neg& op) const {
    if ( op.a.first.GetSize() > config::kMaxBignumSize ) return std::nullopt;
    if ( op.a.second.GetSize() > config::kMaxBignumSize ) return std::nullopt;

    return module->OpBLS_G1_Neg(op);
}

/* Specialization for operation::BLS_G2_Add */
template<> void ExecutorBase<component::G2, operation::BLS_G2_Add>::postprocess(std::shared_ptr<Module> module, operation::BLS_G2_Add& op, const ExecutorBase<component::G2, operation::BLS_G2_Add>::ResultPair& result) const {
    (void)module;

    if ( result.second != std::nullopt  ) {
        const auto curveID = op.curveType.Get();
        const auto g2_v = result.second->first.first.ToTrimmedString();
        const auto g2_w = result.second->first.second.ToTrimmedString();
        const auto g2_x = result.second->second.first.ToTrimmedString();
        const auto g2_y = result.second->second.second.ToTrimmedString();

        G2AddToPool(curveID, g2_v, g2_w, g2_x, g2_y);

        if ( g2_v.size() <= config::kMaxBignumSize ) { Pool_Bignum.Set(g2_v); }
        if ( g2_w.size() <= config::kMaxBignumSize ) { Pool_Bignum.Set(g2_w); }
        if ( g2_x.size() <= config::kMaxBignumSize ) { Pool_Bignum.Set(g2_x); }
        if ( g2_y.size() <= config::kMaxBignumSize ) { Pool_Bignum.Set(g2_y); }
    }
}

template<> std::optional<component::G2> ExecutorBase<component::G2, operation::BLS_G2_Add>::callModule(std::shared_ptr<Module> module, operation::BLS_G2_Add& op) const {
    if ( op.a.first.first.GetSize() > config::kMaxBignumSize ) return std::nullopt;
    if ( op.a.first.second.GetSize() > config::kMaxBignumSize ) return std::nullopt;
    if ( op.a.second.first.GetSize() > config::kMaxBignumSize ) return std::nullopt;
    if ( op.a.second.second.GetSize() > config::kMaxBignumSize ) return std::nullopt;
    if ( op.b.first.first.GetSize() > config::kMaxBignumSize ) return std::nullopt;
    if ( op.b.first.second.GetSize() > config::kMaxBignumSize ) return std::nullopt;
    if ( op.b.second.first.GetSize() > config::kMaxBignumSize ) return std::nullopt;
    if ( op.b.second.second.GetSize() > config::kMaxBignumSize ) return std::nullopt;

    return module->OpBLS_G2_Add(op);
}

/* Specialization for operation::BLS_G2_Mul */
template<> void ExecutorBase<component::G2, operation::BLS_G2_Mul>::postprocess(std::shared_ptr<Module> module, operation::BLS_G2_Mul& op, const ExecutorBase<component::G2, operation::BLS_G2_Mul>::ResultPair& result) const {
    (void)module;

    if ( result.second != std::nullopt  ) {
        const auto curveID = op.curveType.Get();
        const auto g2_v = result.second->first.first.ToTrimmedString();
        const auto g2_w = result.second->first.second.ToTrimmedString();
        const auto g2_x = result.second->second.first.ToTrimmedString();
        const auto g2_y = result.second->second.second.ToTrimmedString();

        G2AddToPool(curveID, g2_v, g2_w, g2_x, g2_y);

        if ( g2_v.size() <= config::kMaxBignumSize ) { Pool_Bignum.Set(g2_v); }
        if ( g2_w.size() <= config::kMaxBignumSize ) { Pool_Bignum.Set(g2_w); }
        if ( g2_x.size() <= config::kMaxBignumSize ) { Pool_Bignum.Set(g2_x); }
        if ( g2_y.size() <= config::kMaxBignumSize ) { Pool_Bignum.Set(g2_y); }
    }
}

template<> std::optional<component::G2> ExecutorBase<component::G2, operation::BLS_G2_Mul>::callModule(std::shared_ptr<Module> module, operation::BLS_G2_Mul& op) const {
    if ( op.a.first.first.GetSize() > config::kMaxBignumSize ) return std::nullopt;
    if ( op.a.first.second.GetSize() > config::kMaxBignumSize ) return std::nullopt;
    if ( op.a.second.first.GetSize() > config::kMaxBignumSize ) return std::nullopt;
    if ( op.a.second.second.GetSize() > config::kMaxBignumSize ) return std::nullopt;
    if ( op.b.GetSize() > config::kMaxBignumSize ) return std::nullopt;

    return module->OpBLS_G2_Mul(op);
}

/* Specialization for operation::BLS_G2_IsEq */
template<> void ExecutorBase<bool, operation::BLS_G2_IsEq>::postprocess(std::shared_ptr<Module> module, operation::BLS_G2_IsEq& op, const ExecutorBase<bool, operation::BLS_G2_IsEq>::ResultPair& result) const {
    (void)module;
    (void)op;
    (void)result;
}

template<> std::optional<bool> ExecutorBase<bool, operation::BLS_G2_IsEq>::callModule(std::shared_ptr<Module> module, operation::BLS_G2_IsEq& op) const {
    if ( op.a.first.first.GetSize() > config::kMaxBignumSize ) return std::nullopt;
    if ( op.a.first.second.GetSize() > config::kMaxBignumSize ) return std::nullopt;
    if ( op.a.second.first.GetSize() > config::kMaxBignumSize ) return std::nullopt;
    if ( op.a.second.second.GetSize() > config::kMaxBignumSize ) return std::nullopt;
    if ( op.b.first.first.GetSize() > config::kMaxBignumSize ) return std::nullopt;
    if ( op.b.first.second.GetSize() > config::kMaxBignumSize ) return std::nullopt;
    if ( op.b.second.first.GetSize() > config::kMaxBignumSize ) return std::nullopt;
    if ( op.b.second.second.GetSize() > config::kMaxBignumSize ) return std::nullopt;

    return module->OpBLS_G2_IsEq(op);
}

/* Specialization for operation::BLS_G2_Neg */
template<> void ExecutorBase<component::G2, operation::BLS_G2_Neg>::postprocess(std::shared_ptr<Module> module, operation::BLS_G2_Neg& op, const ExecutorBase<component::G2, operation::BLS_G2_Neg>::ResultPair& result) const {
    (void)module;

    if ( result.second != std::nullopt  ) {
        const auto curveID = op.curveType.Get();
        const auto g2_v = result.second->first.first.ToTrimmedString();
        const auto g2_w = result.second->first.second.ToTrimmedString();
        const auto g2_x = result.second->second.first.ToTrimmedString();
        const auto g2_y = result.second->second.second.ToTrimmedString();

        G2AddToPool(curveID, g2_v, g2_w, g2_x, g2_y);

        if ( g2_v.size() <= config::kMaxBignumSize ) { Pool_Bignum.Set(g2_v); }
        if ( g2_w.size() <= config::kMaxBignumSize ) { Pool_Bignum.Set(g2_w); }
        if ( g2_x.size() <= config::kMaxBignumSize ) { Pool_Bignum.Set(g2_x); }
        if ( g2_y.size() <= config::kMaxBignumSize ) { Pool_Bignum.Set(g2_y); }
    }
}

template<> std::optional<component::G2> ExecutorBase<component::G2, operation::BLS_G2_Neg>::callModule(std::shared_ptr<Module> module, operation::BLS_G2_Neg& op) const {
    if ( op.a.first.first.GetSize() > config::kMaxBignumSize ) return std::nullopt;
    if ( op.a.first.second.GetSize() > config::kMaxBignumSize ) return std::nullopt;
    if ( op.a.second.first.GetSize() > config::kMaxBignumSize ) return std::nullopt;
    if ( op.a.second.second.GetSize() > config::kMaxBignumSize ) return std::nullopt;

    return module->OpBLS_G2_Neg(op);
}

/* Specialization for operation::Misc */
template<> void ExecutorBase<Buffer, operation::Misc>::postprocess(std::shared_ptr<Module> module, operation::Misc& op, const ExecutorBase<Buffer, operation::Misc>::ResultPair& result) const {
    (void)module;
    (void)op;
    (void)result;
}

template<> std::optional<Buffer> ExecutorBase<Buffer, operation::Misc>::callModule(std::shared_ptr<Module> module, operation::Misc& op) const {
    return module->OpMisc(op);
}

/* Specialization for operation::BLS_HashToG2 */
template<> void ExecutorBase<component::G2, operation::BLS_HashToG2>::postprocess(std::shared_ptr<Module> module, operation::BLS_HashToG2& op, const ExecutorBase<component::G2, operation::BLS_HashToG2>::ResultPair& result) const {
    (void)module;

    if ( result.second != std::nullopt  ) {
        const auto curveID = op.curveType.Get();
        const auto g2_v = result.second->first.first.ToTrimmedString();
        const auto g2_w = result.second->first.second.ToTrimmedString();
        const auto g2_x = result.second->second.first.ToTrimmedString();
        const auto g2_y = result.second->second.second.ToTrimmedString();

        G2AddToPool(curveID, g2_v, g2_w, g2_x, g2_y);

        if ( g2_v.size() <= config::kMaxBignumSize ) { Pool_Bignum.Set(g2_v); }
        if ( g2_w.size() <= config::kMaxBignumSize ) { Pool_Bignum.Set(g2_w); }
        if ( g2_x.size() <= config::kMaxBignumSize ) { Pool_Bignum.Set(g2_x); }
        if ( g2_y.size() <= config::kMaxBignumSize ) { Pool_Bignum.Set(g2_y); }
    }
}

template<> std::optional<component::G2> ExecutorBase<component::G2, operation::BLS_HashToG2>::callModule(std::shared_ptr<Module> module, operation::BLS_HashToG2& op) const {
    return module->OpBLS_HashToG2(op);
}

template <class ResultType, class OperationType>
ExecutorBase<ResultType, OperationType>::ExecutorBase(const uint64_t operationID, const std::map<uint64_t, std::shared_ptr<Module> >& modules, const Options& options) :
    operationID(operationID),
    modules(modules),
    options(options)
{
}

/* Specialization for operation::RSA_generate_key_ex */
template<>
void ExecutorBase<component::RSA_KeyPair, operation::RSA_generate_key_ex>::postprocess(
    std::shared_ptr<Module> module, 
    operation::RSA_generate_key_ex& op,
    const ExecutorBase<component::RSA_KeyPair, operation::RSA_generate_key_ex>::ResultPair& result) const
{
    (void)module;

    if(result.second != std::nullopt){
        const auto& keypair = *result.second;
        const auto& modulus = keypair.n;
        const auto& public_exponent = keypair.e;
        const auto& private_exponent = keypair.d;

        // Store the private key (modulus, private_exponent)
        Pool_RSA_PrivateKey.Set({modulus, private_exponent});

        // Store the public key (modulus, public_exponent)
        Pool_RSA_PublicKey.Set({modulus, public_exponent});

        // Store the key pair (modulus, public_exponent, private_exponent)
        Pool_RSAKeypair.Set({modulus, public_exponent, private_exponent});        
    }
}

template<>
std::optional<component::RSA_KeyPair> ExecutorBase<component::RSA_KeyPair, operation::RSA_generate_key_ex>::callModule(
    std::shared_ptr<Module> module,
    operation::RSA_generate_key_ex& op) const
{


    const uint64_t key_size = op.bits;

    //Validate key size (commonly 1014, 2048, 3072, 4096 bits)
    if(key_size < 1024 || key_size > 16384){ return std::nullopt; }

    if(op.public_exponent > config::kMaxBignumSize){ return std::nullopt; }

    return module->OpRSA_generate_key_ex(op);

}

/* Specialization for operation::SR25519_Verify */
template<> void ExecutorBase<bool, operation::SR25519_Verify>::postprocess(std::shared_ptr<Module> module, operation::SR25519_Verify& op, const ExecutorBase<bool, operation::SR25519_Verify>::ResultPair& result) const {
    (void)module;
    (void)op;
    (void)result;
}

template<> std::optional<bool> ExecutorBase<bool, operation::SR25519_Verify>::callModule(std::shared_ptr<Module> module, operation::SR25519_Verify& op) const {
    return module->OpSR25519_Verify(op);
}

template <class ResultType, class OperationType>
ExecutorBase<ResultType, OperationType>::~ExecutorBase() {
}

/* Filter away the values in the set that are std::nullopt */
template <class ResultType, class OperationType>
typename ExecutorBase<ResultType, OperationType>::ResultSet ExecutorBase<ResultType, OperationType>::filter(const ResultSet& results) const {
    ResultSet ret;

    for (const auto& result : results) {
        if ( result.second == std::nullopt ) {
            continue;
        }

        ret.push_back(result);
    }

    return ret;
}

/* Do not compare ECC_GenerateKeyPair results, because the result can be produced indeterministically */
template <>
void ExecutorBase<component::ECC_KeyPair, operation::ECC_GenerateKeyPair>::compare(const std::vector< std::pair<std::shared_ptr<Module>, operation::ECC_GenerateKeyPair> >& operations, const ResultSet& results, const uint8_t* data, const size_t size) const {
    (void)operations;
    (void)results;
    (void)data;
    (void)size;
}

template <class ResultType, class OperationType>
bool ExecutorBase<ResultType, OperationType>::dontCompare(const OperationType& operation) const {
    (void)operation;

    return false;
}

template <>
bool ExecutorBase<component::Bignum, operation::BignumCalc>::dontCompare(const operation::BignumCalc& operation) const {
    if ( operation.calcOp.Get() == CF_CALCOP("Rand()") ) { return true; }
    if ( operation.calcOp.Get() == CF_CALCOP("Prime()") ) { return true; }

    return false;
}

template <>
bool ExecutorBase<component::ECDSA_Signature, operation::ECDSA_Sign>::dontCompare(const operation::ECDSA_Sign& operation) const {
    if (
            operation.curveType.Get() != CF_ECC_CURVE("ed25519") &&
            operation.curveType.Get() != CF_ECC_CURVE("ed448") ) {
        if ( operation.UseRandomNonce() ) {
            /* Don't compare ECDSA signatures comptued from a randomly generated nonce */
            return true;
        }
    }

    return false;
}

template <>
bool ExecutorBase<component::ECGDSA_Signature, operation::ECGDSA_Sign>::dontCompare(const operation::ECGDSA_Sign& operation) const {
    if (
            operation.curveType.Get() != CF_ECC_CURVE("ed25519") &&
            operation.curveType.Get() != CF_ECC_CURVE("ed448") ) {
        if ( operation.UseRandomNonce() ) {
            /* Don't compare ECGDSA signatures comptued from a randomly generated nonce */
            return true;
        }
    }

    return false;
}

template <>
bool ExecutorBase<component::ECRDSA_Signature, operation::ECRDSA_Sign>::dontCompare(const operation::ECRDSA_Sign& operation) const {
    if (
            operation.curveType.Get() != CF_ECC_CURVE("ed25519") &&
            operation.curveType.Get() != CF_ECC_CURVE("ed448") ) {
        if ( operation.UseRandomNonce() ) {
            /* Don't compare ECRDSA signatures comptued from a randomly generated nonce */
            return true;
        }
    }

    return false;
}

/* OpenSSL DES_EDE3_WRAP randomizes the IV, result is different each time */
template <>
bool ExecutorBase<component::Ciphertext, operation::SymmetricEncrypt>::dontCompare(const operation::SymmetricEncrypt& operation) const {
    if ( operation.cipher.cipherType.Get() == CF_CIPHER("DES_EDE3_WRAP") ) { return true; }

    return false;
}

template <>
bool ExecutorBase<component::Cleartext, operation::SymmetricDecrypt>::dontCompare(const operation::SymmetricDecrypt& operation) const {
    if ( operation.cipher.cipherType.Get() == CF_CIPHER("DES_EDE3_WRAP") ) return true;

    return false;
}

template <>
bool ExecutorBase<component::MAC, operation::CMAC>::dontCompare(const operation::CMAC& operation) const {
    if ( operation.cipher.cipherType.Get() == CF_CIPHER("DES_EDE3_WRAP") ) return true;

    return false;
}

template <>
bool ExecutorBase<component::MAC, operation::HMAC>::dontCompare(const operation::HMAC& operation) const {
    if ( operation.cipher.cipherType.Get() == CF_CIPHER("DES_EDE3_WRAP") ) return true;

    return false;
}

/* Explicit template instantiation */
template class ExecutorBase<component::Digest, operation::Digest>;
template class ExecutorBase<component::MAC, operation::HMAC>;
template class ExecutorBase<component::MAC, operation::UMAC>;
template class ExecutorBase<component::MAC, operation::CMAC>;
template class ExecutorBase<component::Ciphertext, operation::SymmetricEncrypt>;
template class ExecutorBase<component::Cleartext, operation::SymmetricDecrypt>;
template class ExecutorBase<component::Key, operation::KDF_SCRYPT>;
template class ExecutorBase<component::Key, operation::KDF_HKDF>;
template class ExecutorBase<component::Key, operation::KDF_TLS1_PRF>;
template class ExecutorBase<component::Key, operation::KDF_PBKDF>;
template class ExecutorBase<component::Key, operation::KDF_PBKDF1>;
template class ExecutorBase<component::Key, operation::KDF_PBKDF2>;
template class ExecutorBase<component::Key, operation::KDF_ARGON2>;
template class ExecutorBase<component::Key, operation::KDF_SSH>;
template class ExecutorBase<component::Key, operation::KDF_X963>;
template class ExecutorBase<component::Key, operation::KDF_BCRYPT>;
template class ExecutorBase<component::Key, operation::KDF_SP_800_108>;
template class ExecutorBase<component::ECC_PublicKey, operation::ECC_PrivateToPublic>;
template class ExecutorBase<bool, operation::ECC_ValidatePubkey>;
template class ExecutorBase<component::ECC_KeyPair, operation::ECC_GenerateKeyPair>;
template class ExecutorBase<component::ECDSA_Signature, operation::ECDSA_Sign>;
template class ExecutorBase<component::ECGDSA_Signature, operation::ECGDSA_Sign>;
template class ExecutorBase<component::ECRDSA_Signature, operation::ECRDSA_Sign>;
template class ExecutorBase<component::Schnorr_Signature, operation::Schnorr_Sign>;
template class ExecutorBase<bool, operation::ECDSA_Verify>;
template class ExecutorBase<bool, operation::ECGDSA_Verify>;
template class ExecutorBase<bool, operation::ECRDSA_Verify>;
template class ExecutorBase<bool, operation::Schnorr_Verify>;
template class ExecutorBase<component::ECC_PublicKey, operation::ECDSA_Recover>;
template class ExecutorBase<component::Secret, operation::ECDH_Derive>;
template class ExecutorBase<component::Ciphertext, operation::ECIES_Encrypt>;
template class ExecutorBase<component::Cleartext, operation::ECIES_Decrypt>;
template class ExecutorBase<component::ECC_Point, operation::ECC_Point_Add>;
template class ExecutorBase<component::ECC_Point, operation::ECC_Point_Mul>;
template class ExecutorBase<component::ECC_Point, operation::ECC_Point_Neg>;
template class ExecutorBase<component::ECC_Point, operation::ECC_Point_Dbl>;
template class ExecutorBase<component::DH_KeyPair, operation::DH_GenerateKeyPair>;
template class ExecutorBase<component::Bignum, operation::DH_Derive>;
template class ExecutorBase<component::Bignum, operation::BignumCalc>;
template class ExecutorBase<component::Fp2, operation::BignumCalc_Fp2>;
template class ExecutorBase<component::Fp12, operation::BignumCalc_Fp12>;
template class ExecutorBase<component::BLS_PublicKey, operation::BLS_PrivateToPublic>;
template class ExecutorBase<component::G2, operation::BLS_PrivateToPublic_G2>;
template class ExecutorBase<component::BLS_Signature, operation::BLS_Sign>;
template class ExecutorBase<bool, operation::BLS_Verify>;
template class ExecutorBase<component::BLS_BatchSignature, operation::BLS_BatchSign>;
template class ExecutorBase<bool, operation::BLS_BatchVerify>;
template class ExecutorBase<component::G1, operation::BLS_Aggregate_G1>;
template class ExecutorBase<component::G2, operation::BLS_Aggregate_G2>;
template class ExecutorBase<component::Fp12, operation::BLS_Pairing>;
template class ExecutorBase<component::Fp12, operation::BLS_MillerLoop>;
template class ExecutorBase<component::Fp12, operation::BLS_FinalExp>;
template class ExecutorBase<component::G1, operation::BLS_HashToG1>;
template class ExecutorBase<component::G2, operation::BLS_HashToG2>;
template class ExecutorBase<component::G1, operation::BLS_MapToG1>;
template class ExecutorBase<component::G2, operation::BLS_MapToG2>;
template class ExecutorBase<bool, operation::BLS_IsG1OnCurve>;
template class ExecutorBase<bool, operation::BLS_IsG2OnCurve>;
template class ExecutorBase<component::BLS_KeyPair, operation::BLS_GenerateKeyPair>;
template class ExecutorBase<component::G1, operation::BLS_Decompress_G1>;
template class ExecutorBase<component::Bignum, operation::BLS_Compress_G1>;
template class ExecutorBase<component::G2, operation::BLS_Decompress_G2>;
template class ExecutorBase<component::G1, operation::BLS_Compress_G2>;
template class ExecutorBase<component::G1, operation::BLS_G1_Add>;
template class ExecutorBase<component::G1, operation::BLS_G1_Mul>;
template class ExecutorBase<bool, operation::BLS_G1_IsEq>;
template class ExecutorBase<component::G1, operation::BLS_G1_Neg>;
template class ExecutorBase<component::G2, operation::BLS_G2_Add>;
template class ExecutorBase<component::G2, operation::BLS_G2_Mul>;
template class ExecutorBase<bool, operation::BLS_G2_IsEq>;
template class ExecutorBase<component::G2, operation::BLS_G2_Neg>;
template class ExecutorBase<Buffer, operation::Misc>;
template class ExecutorBase<bool, operation::SR25519_Verify>;
template class ExecutorBase<component::RSA_KeyPair, operation::RSA_generate_key_ex>;