void test(const operation::Digest& op, const std::optional<component::Digest>& result) {
    if ( result == std::nullopt ) {
        return;
    }

    {
        const auto expectedSize = repository::DigestSize(op.digestType.Get());

        if ( expectedSize != std::nullopt ) {
            if ( result->GetSize() != *expectedSize ) {
                printf("Expected vs actual digest size: %zu / %zu\n", *expectedSize, result->GetSize());
                abort();
            }
        }
    }

#if 0
    if ( op.digestType.Is(CF_DIGEST("SHA1")) ) {
        /* https://words.filippo.io/dispatches/seeds-bounty/ */

        static const std::vector< std::vector<uint8_t> > hashes{
            /* NIST P-192 */
            {
                0x30, 0x45, 0xAE, 0x6F, 0xC8, 0x42, 0x2F, 0x64, 0xED, 0x57,
                    0x95, 0x28, 0xD3, 0x81, 0x20, 0xEA, 0xE1, 0x21, 0x96, 0xD5,
            },
            /* NIST P-224 */
            {
                0xBD, 0x71, 0x34, 0x47, 0x99, 0xD5, 0xC7, 0xFC, 0xDC, 0x45,
                0xB5, 0x9F, 0xA3, 0xB9, 0xAB, 0x8F, 0x6A, 0x94, 0x8B, 0xC5,
            },
            /* NIST P-256 */
            {
                0xC4, 0x9D, 0x36, 0x08, 0x86, 0xE7, 0x04, 0x93, 0x6A, 0x66,
                0x78, 0xE1, 0x13, 0x9D, 0x26, 0xB7, 0x81, 0x9F, 0x7E, 0x90,
            },
            /* NIST P-384 */
            {
                0xA3, 0x35, 0x92, 0x6A, 0xA3, 0x19, 0xA2, 0x7A, 0x1D, 0x00,
                0x89, 0x6A, 0x67, 0x73, 0xA4, 0x82, 0x7A, 0xCD, 0xAC, 0x73,
            },
            /* NIST P-521 */
            {
                0xD0, 0x9E, 0x88, 0x00, 0x29, 0x1C, 0xB8, 0x53, 0x96, 0xCC,
                0x67, 0x17, 0x39, 0x32, 0x84, 0xAA, 0xA0, 0xDA, 0x64, 0xBA,
            },
            /* ANSI prime192v2 */
            {
                0x31, 0xA9, 0x2E, 0xE2, 0x02, 0x9F, 0xD1, 0x0D, 0x90, 0x1B,
                0x11, 0x3E, 0x99, 0x07, 0x10, 0xF0, 0xD2, 0x1A, 0xC6, 0xB6,
            },
            /* ANSI prime192v3 */
            {
                0xC4, 0x69, 0x68, 0x44, 0x35, 0xDE, 0xB3, 0x78, 0xC4, 0xB6,
                0x5C, 0xA9, 0x59, 0x1E, 0x2A, 0x57, 0x63, 0x05, 0x9A, 0x2E,
            },
            /* ANSI prime239v1 */
            {
                0xE4, 0x3B, 0xB4, 0x60, 0xF0, 0xB8, 0x0C, 0xC0, 0xC0, 0xB0,
                0x75, 0x79, 0x8E, 0x94, 0x80, 0x60, 0xF8, 0x32, 0x1B, 0x7D,
            },
            /* ANSI prime239v2 */
            {
                0xE8, 0xB4, 0x01, 0x16, 0x04, 0x09, 0x53, 0x03, 0xCA, 0x3B,
                0x80, 0x99, 0x98, 0x2B, 0xE0, 0x9F, 0xCB, 0x9A, 0xE6, 0x16,
            },
            /* ANSI prime239v3 */
            {
                0x7D, 0x73, 0x74, 0x16, 0x8F, 0xFE, 0x34, 0x71, 0xB6, 0x0A,
                0x85, 0x76, 0x86, 0xA1, 0x94, 0x75, 0xD3, 0xBF, 0xA2, 0xFF,
            },
            /* NIST B-163 */
            {
                0x85, 0xE2, 0x5B, 0xFE, 0x5C, 0x86, 0x22, 0x6C, 0xDB, 0x12,
                0x01, 0x6F, 0x75, 0x53, 0xF9, 0xD0, 0xE6, 0x93, 0xA2, 0x68,
            },
            /* NIST B-233 */
            {
                0x74, 0xD5, 0x9F, 0xF0, 0x7F, 0x6B, 0x41, 0x3D, 0x0E, 0xA1,
                0x4B, 0x34, 0x4B, 0x20, 0xA2, 0xDB, 0x04, 0x9B, 0x50, 0xC3,
            },
            /* NIST B-283 */
            {
                0x77, 0xE2, 0xB0, 0x73, 0x70, 0xEB, 0x0F, 0x83, 0x2A, 0x6D,
                0xD5, 0xB6, 0x2D, 0xFC, 0x88, 0xCD, 0x06, 0xBB, 0x84, 0xBE,
            },
            /* NIST B-409 */
            {
                0x40, 0x99, 0xB5, 0xA4, 0x57, 0xF9, 0xD6, 0x9F, 0x79, 0x21,
                0x3D, 0x09, 0x4C, 0x4B, 0xCD, 0x4D, 0x42, 0x62, 0x21, 0x0B,
            },
            /* NIST B-571 */
            {
                0x2A, 0xA0, 0x58, 0xF7, 0x3A, 0x0E, 0x33, 0xAB, 0x48, 0x6B,
                0x0F, 0x61, 0x04, 0x10, 0xC5, 0x3A, 0x7F, 0x13, 0x23, 0x10,
            },
        };

        for (const auto& hash : hashes) {
            if ( result->Get() == hash ) abort();
        }
    }
#endif

    checkZeroResult(result);
}

void test(const operation::HMAC& op, const std::optional<component::MAC>& result) {
    if ( result == std::nullopt ) {
        return;
    }

    {
        const auto expectedSize = repository::DigestSize(op.digestType.Get());

        if ( expectedSize != std::nullopt ) {
            if ( result->GetSize() != *expectedSize ) {
                printf("Expected vs actual digest size: %zu / %zu\n", *expectedSize, result->GetSize());
                abort();
            }
        }
    }

    checkZeroResult(result);
}

void test(const operation::UMAC& op, const std::optional<component::MAC>& result) {
    if ( result == std::nullopt ) {
        return;
    }

    if (
            ( op.type == 0 && result->GetSize() > (32/8) ) ||
            ( op.type == 1 && result->GetSize() > (64/8) ) ||
            ( op.type == 2 && result->GetSize() > (96/8) ) ||
            ( op.type == 3 && result->GetSize() > (128/8) )
    ) {
        printf("UMAC: Overlong result: %zu\n", result->GetSize());
        abort();
    }
}

static void test_ChaCha20_Poly1305_IV(const operation::SymmetricEncrypt& op, const std::optional<component::Ciphertext>& result) {
    using fuzzing::datasource::ID;

    /*
     * OpenSSL CVE-2019-1543
     * https://www.openssl.org/news/secadv/20190306.txt
     */

    if ( op.cipher.cipherType.Get() != CF_CIPHER("CHACHA20_POLY1305") ) {
        return;
    }

    if ( result == std::nullopt ) {
        return;
    }

    if ( op.cipher.iv.GetSize() > 12 ) {
        abort();
    }
}

static void test_XChaCha20_Poly1305_IV(const operation::SymmetricEncrypt& op, const std::optional<component::Ciphertext>& result) {
    using fuzzing::datasource::ID;

    if ( op.cipher.cipherType.Get() != CF_CIPHER("XCHACHA20_POLY1305") ) {
        return;
    }

    if ( result == std::nullopt ) {
        return;
    }

    if ( op.cipher.iv.GetSize() != 24 ) {
        printf("XChaCha20-Poly1305 succeeded with an IV of %zu bytes large, but only IVs of 24 bytes are valid\n", op.cipher.iv.GetSize());
        abort();
    }
}

static void test_AES_CCM_Wycheproof(const operation::SymmetricEncrypt& op, const std::optional<component::Ciphertext>& result) {
    bool fail = false;

    if ( result == std::nullopt ) {
        return;
    }

    switch ( op.cipher.cipherType.Get() ) {
        case CF_CIPHER("AES_128_CCM"):
        case CF_CIPHER("AES_192_CCM"):
        case CF_CIPHER("AES_256_CCM"):
            break;
        default:
            return;
    }

    if ( op.cipher.iv.GetSize() < 7 || op.cipher.iv.GetSize() > 13 ) {
        printf("AES CCM: Invalid IV size\n");
        fail = true;
    }

    if ( result->tag != std::nullopt ) {
        static const std::vector<size_t> validTagSizes = {4, 6, 8, 10, 12, 14, 16};

        if ( std::find(validTagSizes.begin(), validTagSizes.end(), result->tag->GetSize()) == validTagSizes.end() ) {
            printf("AES CCM: Invalid tag size\n");
            fail = true;
        }
    }

    if ( fail == true ) {
        printf("AES CCM tests based on Wycheproof: https://github.com/google/wycheproof/blob/4672ff74d68766e7785c2cac4c597effccef2c5c/testvectors/aes_ccm_test.json#L11\n");
        abort();
    }
}

static void test_AES_GCM_Wycheproof(const operation::SymmetricEncrypt& op, const std::optional<component::Ciphertext>& result) {
    bool fail = false;

    if ( result == std::nullopt ) {
        return;
    }

    switch ( op.cipher.cipherType.Get() ) {
        case CF_CIPHER("AES_128_GCM"):
        case CF_CIPHER("AES_192_GCM"):
        case CF_CIPHER("AES_256_GCM"):
            break;
        default:
            return;
    }

    if ( op.cipher.iv.GetSize() == 0 ) {
        printf("AES GCM: Invalid IV size\n");
        fail = true;
    }

    if ( fail == true ) {
        printf("AES GCM tests based on Wycheproof: https://github.com/google/wycheproof/blob/4672ff74d68766e7785c2cac4c597effccef2c5c/testvectors/aes_gcm_test.json#L13\n");
        abort();
    }
}

void test(const operation::SymmetricEncrypt& op, const std::optional<component::Ciphertext>& result) {
    test_ChaCha20_Poly1305_IV(op, result);
    test_XChaCha20_Poly1305_IV(op, result);
    test_AES_CCM_Wycheproof(op, result);
    test_AES_GCM_Wycheproof(op, result);
}

void test(const operation::SymmetricDecrypt& op, const std::optional<component::Cleartext>& result) {
    (void)op;
    (void)result;
}

void test(const operation::CMAC& op, const std::optional<component::MAC>& result) {
    (void)op;
    (void)result;
}

void test(const operation::KDF_SCRYPT& op, const std::optional<component::Key>& result) {
    verifyKeySize(op, result);
}

static void test_HKDF_OutputSize(const operation::KDF_HKDF& op, const std::optional<component::Key>& result) {
    if ( result == std::nullopt ) {
        return;
    }

    const auto expectedSize = repository::DigestSize(op.digestType.Get());

    if ( expectedSize == std::nullopt ) {
        return;
    }

    const size_t maxOutputSize = 255 * *expectedSize;

    if ( result->GetSize() > maxOutputSize ) {
        printf("The output size of HKDF (%zu) is more than 255 * the size of the hash digest (%zu)\n", result->GetSize(), maxOutputSize);
        abort();
    }
}

void test(const operation::KDF_HKDF& op, const std::optional<component::Key>& result) {
    verifyKeySize(op, result);

    test_HKDF_OutputSize(op, result);
}

void test(const operation::KDF_TLS1_PRF& op, const std::optional<component::Key>& result) {
    verifyKeySize(op, result);
}

void test(const operation::KDF_PBKDF& op, const std::optional<component::Key>& result) {
    verifyKeySize(op, result);
}

void test(const operation::KDF_PBKDF1& op, const std::optional<component::Key>& result) {
    verifyKeySize(op, result);
}

void test(const operation::KDF_PBKDF2& op, const std::optional<component::Key>& result) {
    verifyKeySize(op, result);
}

void test(const operation::KDF_ARGON2& op, const std::optional<component::Key>& result) {
    verifyKeySize(op, result);
}

void test(const operation::KDF_SSH& op, const std::optional<component::Key>& result) {
    verifyKeySize(op, result);
}

void test(const operation::KDF_X963& op, const std::optional<component::Key>& result) {
    verifyKeySize(op, result);
}

void test(const operation::KDF_BCRYPT& op, const std::optional<component::Key>& result) {
    verifyKeySize(op, result);
}

void test(const operation::KDF_SP_800_108& op, const std::optional<component::Key>& result) {
    verifyKeySize(op, result);
}

void test(const operation::KDF_SRTP& op, const std::optional<component::Key3>& result) {
    (void)op;
    (void)result;
}

void test(const operation::KDF_SRTCP& op, const std::optional<component::Key3>& result) {
    (void)op;
    (void)result;
}

static void test_ECC_PrivateKey(const uint64_t curveID, const std::string priv) {
    /* Disabled until all modules comply by default */
    return;

    /* Private key may be 0 with these curves */
    if ( IsSpecialCurve(curveID) ) {
        return;
    }

    if ( priv == "0" ) {
        std::cout << "0 is an invalid elliptic curve private key" << std::endl;
        ::abort();
    }
}

void test(const operation::ECC_PrivateToPublic& op, const std::optional<component::ECC_PublicKey>& result) {
    if ( result != std::nullopt ) {
        test_ECC_PrivateKey(op.curveType.Get(), op.priv.ToTrimmedString());
    }
}

void test(const operation::ECC_ValidatePubkey& op, const std::optional<bool>& result) {
    (void)op;
    (void)result;
}

void test(const operation::ECC_GenerateKeyPair& op, const std::optional<component::ECC_KeyPair>& result) {
    if ( result != std::nullopt ) {
        test_ECC_PrivateKey(op.curveType.Get(), result->priv.ToTrimmedString());
    }
}

static void test_ECDSA_Signature(const uint64_t curveID, const std::string R, const std::string S) {
    if ( IsSpecialCurve(curveID) ) {
        return;
    }

    const boost::multiprecision::cpp_int r(R), s(S);

    if ( r < 1 ) {
        std::cout << "ECDSA signature invalid: R < 1" << std::endl;
        ::abort();
    }
    if ( s < 1 ) {
        std::cout << "ECDSA signature invalid: S < 1" << std::endl;
        ::abort();
    }

    const auto O = cryptofuzz::repository::ECC_CurveToOrder(curveID);
    if ( O == std::nullopt ) {
        return;
    }

    const boost::multiprecision::cpp_int o(*O);

    if ( r >= o ) {
        std::cout << "ECDSA signature invalid: R >= order" << std::endl;
        ::abort();
    }

    if ( s >= o ) {
        std::cout << "ECDSA signature invalid: S >= order" << std::endl;
        ::abort();
    }
}

static void test_BIP340_Schnorr_Signature(const uint64_t curveID, const std::string R, const std::string S) {
    boost::multiprecision::cpp_int r(R);
    boost::multiprecision::cpp_int s(S);
    if ( r < 1 ) {
        std::cout << "BIP340 Schnorr signature invalid: R < 1" << std::endl;
        ::abort();
    }
    if ( s < 1 ) {
        std::cout << "BIP340 Schnorr signature invalid: S < 1" << std::endl;
        ::abort();
    }

    const auto prime = cryptofuzz::repository::ECC_CurveToPrime(curveID);
    if ( prime != std::nullopt ) {
        const boost::multiprecision::cpp_int p(*prime);
        CF_ASSERT(r < p, "BIP340 Schnorr signature R should be less than curve P");
    }

    const auto order = cryptofuzz::repository::ECC_CurveToOrder(curveID);
    if ( order != std::nullopt ) {
        const boost::multiprecision::cpp_int n(*order);
        CF_ASSERT(s < n, "BIP340 Schnorr signature S should be less than curve N");
    }
}

void test(const operation::ECCSI_Sign& op, const std::optional<component::ECCSI_Signature>& result) {
    (void)op;
    (void)result;
}
void test(const operation::ECDSA_Sign& op, const std::optional<component::ECDSA_Signature>& result) {
    if ( result != std::nullopt ) {
        test_ECC_PrivateKey(op.curveType.Get(), op.priv.ToTrimmedString());

        if (
                op.UseSpecifiedNonce() == true &&
                !IsSpecialCurve(op.curveType.Get()) &&
                op.nonce.ToTrimmedString() == "0"
           ) {
            std::cout << "0 is an invalid ECDSA nonce" << std::endl;
            ::abort();
        }

        test_ECDSA_Signature(op.curveType.Get(),
                result->signature.first.ToTrimmedString(),
                result->signature.second.ToTrimmedString());
    }
}

void test(const operation::ECGDSA_Sign& op, const std::optional<component::ECGDSA_Signature>& result) {
    if ( result != std::nullopt ) {
        test_ECC_PrivateKey(op.curveType.Get(), op.priv.ToTrimmedString());

        if (
                op.UseSpecifiedNonce() == true &&
                !IsSpecialCurve(op.curveType.Get()) &&
                op.nonce.ToTrimmedString() == "0"
           ) {
            std::cout << "0 is an invalid ECGDSA nonce" << std::endl;
            ::abort();
        }

        test_ECDSA_Signature(op.curveType.Get(),
                result->signature.first.ToTrimmedString(),
                result->signature.second.ToTrimmedString());
    }
}

void test(const operation::ECRDSA_Sign& op, const std::optional<component::ECRDSA_Signature>& result) {
    if ( result != std::nullopt ) {
        test_ECC_PrivateKey(op.curveType.Get(), op.priv.ToTrimmedString());

        if (
                op.UseSpecifiedNonce() == true &&
                !IsSpecialCurve(op.curveType.Get()) &&
                op.nonce.ToTrimmedString() == "0"
           ) {
            std::cout << "0 is an invalid ECRDSA nonce" << std::endl;
            ::abort();
        }

        test_ECDSA_Signature(op.curveType.Get(),
                result->signature.first.ToTrimmedString(),
                result->signature.second.ToTrimmedString());
    }
}

void test(const operation::Schnorr_Sign& op, const std::optional<component::Schnorr_Signature>& result) {
    if ( result != std::nullopt ) {
        test_ECC_PrivateKey(op.curveType.Get(), op.priv.ToTrimmedString());

        if (
                op.UseSpecifiedNonce() == true &&
                !IsSpecialCurve(op.curveType.Get()) &&
                op.nonce.ToTrimmedString() == "0"
           ) {
            std::cout << "0 is an invalid Schnorr nonce" << std::endl;
            ::abort();
        }

        test_BIP340_Schnorr_Signature(op.curveType.Get(),
                result->signature.first.ToTrimmedString(),
                result->signature.second.ToTrimmedString());
    }
}

void test(const operation::ECCSI_Verify& op, const std::optional<bool>& result) {
    (void)op;
    (void)result;
}

void test(const operation::ECDSA_Verify& op, const std::optional<bool>& result) {
    if ( result != std::nullopt && *result == true ) {
        test_ECDSA_Signature(op.curveType.Get(),
                op.signature.signature.first.ToTrimmedString(),
                op.signature.signature.second.ToTrimmedString());
    }
}

void test(const operation::ECGDSA_Verify& op, const std::optional<bool>& result) {
    if ( result != std::nullopt && *result == true ) {
        test_ECDSA_Signature(op.curveType.Get(),
                op.signature.signature.first.ToTrimmedString(),
                op.signature.signature.second.ToTrimmedString());
    }
}

void test(const operation::ECRDSA_Verify& op, const std::optional<bool>& result) {
    if ( result != std::nullopt && *result == true ) {
        test_ECDSA_Signature(op.curveType.Get(),
                op.signature.signature.first.ToTrimmedString(),
                op.signature.signature.second.ToTrimmedString());
    }
}

void test(const operation::Schnorr_Verify& op, const std::optional<bool>& result) {
    if ( result != std::nullopt && *result == true ) {
        test_BIP340_Schnorr_Signature(op.curveType.Get(),
                op.signature.signature.first.ToTrimmedString(),
                op.signature.signature.second.ToTrimmedString());
    }
}

void test(const operation::ECDSA_Recover& op, const std::optional<component::ECC_PublicKey>& result) {
    if ( result != std::nullopt ) {
        if ( op.id > 3 ) {
            std::cout << "Invalid recovery ID" << std::endl;
            ::abort();
        }
    }
    if ( result != std::nullopt ) {
        test_ECDSA_Signature(op.curveType.Get(),
                op.signature.first.ToTrimmedString(),
                op.signature.second.ToTrimmedString());
    }
}

void test(const operation::DSA_Verify& op, const std::optional<bool>& result) {
    (void)op;

    if ( result == std::nullopt || *result == false ) {
        return;
    }

    if ( !op.signature.first.IsPositive() ) {
        std::cout << "DSA signature must be rejected if R is smaller than 1" << std::endl;
        ::abort();
    }
    if ( !op.signature.second.IsPositive() ) {
        std::cout << "DSA signature must be rejected is S is smaller than 1" << std::endl;
        ::abort();
    }

    /* Q > R */
    if ( op.signature.first.ToTrimmedString().size() > op.parameters.q.ToTrimmedString().size() ) {
        std::cout << "DSA signature must be rejected if R is larger than Q" << std::endl;
        ::abort();
    }
    /* Q > S */
    if ( op.signature.second.ToTrimmedString().size() > op.parameters.q.ToTrimmedString().size() ) {
        std::cout << "DSA signature must be rejected if S is larger than Q" << std::endl;
        ::abort();
    }
}

void test(const operation::DSA_Sign& op, const std::optional<component::DSA_Signature>& result) {
    if ( result == std::nullopt ) {
        return;
    }

    if ( !result->signature.first.IsPositive() ) {
        std::cout << "DSA signature R must be larger than 0" << std::endl;
        ::abort();
    }
    if ( !result->signature.second.IsPositive() ) {
        std::cout << "DSA signature S must be larger than 0" << std::endl;
        ::abort();
    }

    /* Q > R */
    if ( result->signature.first.ToTrimmedString().size() > op.parameters.q.ToTrimmedString().size() ) {
        std::cout << "DSA signature R must be smaller than P" << std::endl;
        ::abort();
    }
    /* Q > S */
    if ( result->signature.second.ToTrimmedString().size() > op.parameters.q.ToTrimmedString().size() ) {
        std::cout << "DSA signature S must be smaller than Q" << std::endl;
        ::abort();
    }

    /* R > 0 */
    if ( !result->signature.first.IsPositive() ) {
        std::cout << "DSA signature R must be larger than 0" << std::endl;
        ::abort();
    }
    /* S > 0 */
    if ( !result->signature.second.IsPositive() ) {
        std::cout << "DSA signature R must be larger than 0" << std::endl;
        ::abort();
    }
}

void test(const operation::DSA_GenerateParameters& op, const std::optional<component::DSA_Parameters>& result) {
    (void)op;

    if ( result == std::nullopt ) {
        return;
    }

    /* Larger than 0 */
    if ( !result->p.IsPositive() ) {
        std::cout << "DSA P parameter must be larger than 0" << std::endl;
        ::abort();
    }
    if ( !result->q.IsPositive() ) {
        std::cout << "DSA Q parameter must be larger than 0" << std::endl;
        ::abort();
    }
    if ( !result->g.IsPositive() ) {
        std::cout << "DSA G parameter must be larger than 0" << std::endl;
        ::abort();
    }

    /* P > Q */
    if ( result->q.ToTrimmedString().size() > result->p.ToTrimmedString().size() ) {
        std::cout << "DSA Q must be smaller than P" << std::endl;
        ::abort();
    }

    /* P > G */
    if ( result->q.ToTrimmedString().size() > result->p.ToTrimmedString().size() ) {
        std::cout << "DSA G must be smaller than P" << std::endl;
        ::abort();
    }

    /* G != 1 */
    if ( result->p.ToTrimmedString() == "1" ) {
        std::cout << "DSA G must not be 1" << std::endl;
        ::abort();
    }

    /* P, Q must be prime */
    if ( isComposite(result->p.ToTrimmedString()) ) {
        std::cout << "DSA P must be prime" << std::endl;
        ::abort();
    }

    if ( isComposite(result->q.ToTrimmedString()) ) {
        std::cout << "DSA Q must be prime" << std::endl;
        ::abort();
    }
}

void test(const operation::DSA_PrivateToPublic& op, const std::optional<component::Bignum>& result) {
    (void)op;
    (void)result;
}

void test(const operation::DSA_GenerateKeyPair& op, const std::optional<component::DSA_KeyPair>& result) {
    if ( result == std::nullopt ) {
        return;
    }

    if ( !result->first.IsPositive() ) {
        std::cout << "Private key must be larger than 0" << std::endl;
        ::abort();
    }

    /* Q > priv */
    if ( result->first.ToTrimmedString().size() > op.q.ToTrimmedString().size() ) {
        std::cout << "Q must be larger than private key" << std::endl;
        ::abort();
    }
}

void test(const operation::ECDH_Derive& op, const std::optional<component::Secret>& result) {
    (void)op;
    (void)result;
}

void test(const operation::ECIES_Encrypt& op, const std::optional<component::Ciphertext>& result) {
    /* TODO check minimum size? */
    (void)op;
    (void)result;
}

void test(const operation::ECIES_Decrypt& op, const std::optional<component::Cleartext>& result) {
    (void)op;
    (void)result;
}

void test(const operation::ECC_Point_Add& op, const std::optional<component::ECC_Point>& result) {
    (void)op;
    (void)result;
}

void test(const operation::ECC_Point_Sub& op, const std::optional<component::ECC_Point>& result) {
    if ( result == std::nullopt ) {
        return;
    }

    if ( !(op.a.first == op.b.first) ) {
        return;
    }

    if ( !(op.a.second == op.b.second) ) {
        return;
    }

    if ( !result->first.IsZero() || !result->second.IsZero() ) {
        std::cout << "Subtracting equal points should result in point at infinity" << std::endl;
        ::abort();
    }
}

void test(const operation::ECC_Point_Mul& op, const std::optional<component::ECC_Point>& result) {
    (void)op;
    (void)result;
}

void test(const operation::ECC_Point_Neg& op, const std::optional<component::ECC_Point>& result) {
    (void)op;
    (void)result;
}

void test(const operation::ECC_Point_Dbl& op, const std::optional<component::ECC_Point>& result) {
    (void)op;
    (void)result;
}

void test(const operation::ECC_Point_Cmp& op, const std::optional<bool>& result) {
    (void)op;
    (void)result;
}

void test(const operation::DH_GenerateKeyPair& op, const std::optional<component::DH_KeyPair>& result) {
    (void)op;
    (void)result;
}

void test(const operation::DH_Derive& op, const std::optional<component::Bignum>& result) {
    (void)op;
    (void)result;
}

void test(const operation::BLS_PrivateToPublic& op, const std::optional<component::BLS_PublicKey>& result) {
    (void)op;
    (void)result;
}

void test(const operation::BLS_PrivateToPublic_G2& op, const std::optional<component::G2>& result) {
    (void)op;
    (void)result;
}

void test(const operation::BLS_Sign& op, const std::optional<component::BLS_Signature>& result) {
    (void)op;
    (void)result;
}

void test(const operation::BLS_Verify& op, const std::optional<bool>& result) {
    (void)op;
    (void)result;
}

void test(const operation::BLS_BatchSign& op, const std::optional<component::BLS_BatchSignature>& result) {
    (void)op;
    (void)result;
}

void test(const operation::BLS_BatchVerify& op, const std::optional<bool>& result) {
    (void)op;
    (void)result;
}

void test(const operation::BLS_Aggregate_G1& op, const std::optional<component::G1>& result) {
    (void)op;
    (void)result;
}

void test(const operation::BLS_Aggregate_G2& op, const std::optional<component::G2>& result) {
    (void)op;
    (void)result;
}

void test(const operation::BLS_Pairing& op, const std::optional<component::Fp12>& result) {
    (void)op;
    (void)result;
}

void test(const operation::BLS_MillerLoop& op, const std::optional<component::Fp12>& result) {
    (void)op;
    (void)result;
}

void test(const operation::BLS_FinalExp& op, const std::optional<component::Fp12>& result) {
    (void)op;
    (void)result;
}

void test(const operation::BLS_HashToG1& op, const std::optional<component::G1>& result) {
    (void)op;
    (void)result;
}

void test(const operation::BLS_HashToG2& op, const std::optional<component::G2>& result) {
    (void)op;
    (void)result;
}

void test(const operation::BLS_MapToG1& op, const std::optional<component::G1>& result) {
    (void)op;
    (void)result;
}

void test(const operation::BLS_MapToG2& op, const std::optional<component::G2>& result) {
    (void)op;
    (void)result;
}

void test(const operation::BLS_IsG1OnCurve& op, const std::optional<bool>& result) {
    (void)op;
    (void)result;
}

void test(const operation::BLS_IsG2OnCurve& op, const std::optional<bool>& result) {
    (void)op;
    (void)result;
}

void test(const operation::BLS_GenerateKeyPair& op, const std::optional<component::BLS_KeyPair>& result) {
    (void)op;
    (void)result;
}

void test(const operation::BLS_Decompress_G1& op, const std::optional<component::G1>& result) {
    (void)op;
    (void)result;
}

void test(const operation::BLS_Compress_G1& op, const std::optional<component::Bignum>& result) {
    (void)op;
    (void)result;
}

void test(const operation::BLS_Decompress_G2& op, const std::optional<component::G2>& result) {
    (void)op;
    (void)result;
}

void test(const operation::BLS_Compress_G2& op, const std::optional<component::G1>& result) {
    (void)op;
    (void)result;
}

void test(const operation::BLS_G1_Add& op, const std::optional<component::G1>& result) {
    (void)op;
    (void)result;
}

void test(const operation::BLS_G1_Mul& op, const std::optional<component::G1>& result) {
    (void)op;
    (void)result;
}

void test(const operation::BLS_G1_IsEq& op, const std::optional<bool>& result) {
    (void)op;
    (void)result;
}

void test(const operation::BLS_G1_Neg& op, const std::optional<component::G1>& result) {
    (void)op;
    (void)result;
}

void test(const operation::BLS_G2_Add& op, const std::optional<component::G2>& result) {
    (void)op;
    (void)result;
}

void test(const operation::BLS_G2_Mul& op, const std::optional<component::G2>& result) {
    (void)op;
    (void)result;
}

void test(const operation::BLS_G2_IsEq& op, const std::optional<bool>& result) {
    (void)op;
    (void)result;
}

void test(const operation::BLS_G2_Neg& op, const std::optional<component::G2>& result) {
    (void)op;
    (void)result;
}

void test(const operation::BLS_G1_MultiExp& op, const std::optional<component::G1>& result) {
    (void)op;
    (void)result;
}

void test(const operation::Misc& op, const std::optional<Buffer>& result) {
    (void)op;
    (void)result;
}

void test(const operation::SR25519_Verify& op, const std::optional<bool>& result) {
    (void)op;
    (void)result;
}

void test(const operation::BignumCalc& op, const std::optional<component::Bignum>& result) {
    if ( result == std::nullopt ) {
        return;
    }

    using namespace BignumCalc;

    const auto calcOp = op.calcOp.Get();

    if (
            calcOp != CF_CALCOP("IsPrime(A)") &&
            calcOp != CF_CALCOP("Prime()") ) {
        /* Negative numbers are not supported yet */
        if (    op.bn0.IsNegative() ||
                op.bn1.IsNegative() ||
                op.bn2.IsNegative() ) {
            return;
        }
    }

    /* Modular calculations are not supported yet */
    if ( op.modulo != std::nullopt ) {
        return;
    }

    switch ( calcOp ) {
        case    CF_CALCOP("Add(A,B)"):
            if (    SmallerThan(*result, op.bn0) ||
                    SmallerThan(*result, op.bn1) ) {
                Abort("Result is smaller than its operands", repository::CalcOpToString(calcOp));
            }
            break;
        case    CF_CALCOP("Div(A,B)"):
            if ( IsZero(op.bn1) ) {
                Abort("Division by zero should not produce a result", repository::CalcOpToString(calcOp));
            }

            if ( LargerThan(*result, op.bn0) ) {
                Abort("Result is larger than the dividend", repository::CalcOpToString(calcOp));
            }
            break;
        case    CF_CALCOP("Mul(A,B)"):
            if ( IsZero(op.bn0) || IsZero(op.bn1) ) {
                if ( !IsZero(*result) ) {
                    Abort("Result of Mul with zero operand is not zero", repository::CalcOpToString(calcOp));
                }
            }
            break;
        case    CF_CALCOP("Mod(A,B)"):
            BignumCalc::AssertModResult(*result, op.bn1, "Mod");
            break;
        case    CF_CALCOP("ExpMod(A,B,C)"):
            BignumCalc::AssertModResult(*result, op.bn2, "ExpMod");
            break;
        case    CF_CALCOP("AddMod(A,B,C)"):
            BignumCalc::AssertModResult(*result, op.bn2, "AddMod");
            break;
        case    CF_CALCOP("SubMod(A,B,C)"):
            BignumCalc::AssertModResult(*result, op.bn2, "SubMod");
            break;
        case    CF_CALCOP("MulMod(A,B,C)"):
            BignumCalc::AssertModResult(*result, op.bn2, "MulMod");
            break;
        case    CF_CALCOP("SqrMod(A,B)"):
            BignumCalc::AssertModResult(*result, op.bn1, "SqrMod");
            break;
        case    CF_CALCOP("SqrtMod(A,B)"):
            BignumCalc::AssertModResult(*result, op.bn1, "SqrtMod");
            break;
        case    CF_CALCOP("ModLShift(A,B,C)"):
            BignumCalc::AssertModResult(*result, op.bn2, "ModLShift");
            break;
        case    CF_CALCOP("Bit(A,B)"):
            BignumCalc::AssertBinary(*result, "Bit");
            break;
        case    CF_CALCOP("IsCoprime(A,B)"):
            BignumCalc::AssertBinary(*result, "IsCoprime");
            break;
        case    CF_CALCOP("IsEq(A,B)"):
            BignumCalc::AssertBinary(*result, "IsEq");
            break;
        case    CF_CALCOP("IsGt(A,B)"):
            BignumCalc::AssertBinary(*result, "IsGt");
            break;
        case    CF_CALCOP("IsGte(A,B)"):
            BignumCalc::AssertBinary(*result, "IsGte");
            break;
        case    CF_CALCOP("IsLt(A,B)"):
            BignumCalc::AssertBinary(*result, "IsLt");
            break;
        case    CF_CALCOP("IsLte(A,B)"):
            BignumCalc::AssertBinary(*result, "IsLte");
            break;
        case    CF_CALCOP("IsEven(A)"):
            BignumCalc::AssertBinary(*result, "IsEven");
            break;
        case    CF_CALCOP("IsOdd(A)"):
            BignumCalc::AssertBinary(*result, "IsOdd");
            break;
        case    CF_CALCOP("IsOne(A)"):
            BignumCalc::AssertBinary(*result, "IsOne");
            break;
        case    CF_CALCOP("IsPow2(A)"):
            BignumCalc::AssertBinary(*result, "IsPow2");
            break;
        case    CF_CALCOP("IsPrime(A)"):
            BignumCalc::AssertBinary(*result, "IsPrime");
            if ( !op.bn0.IsPositive() ) {
                BignumCalc::AssertZero(*result, "IsPrime");
            }
            if ( result->IsOne() ) {
                if ( op.bn0.ToTrimmedString() != "2" ) {
                    BignumCalc::AssertOdd(op.bn0, "IsPrime");
                }
            }
            break;
        case    CF_CALCOP("IsZero(A)"):
            BignumCalc::AssertBinary(*result, "IsZero");
            break;
        case    CF_CALCOP("IsSquare(A)"):
            BignumCalc::AssertBinary(*result, "IsSquare");
            break;
        case    CF_CALCOP("IsPower(A)"):
            BignumCalc::AssertBinary(*result, "IsPower");
            break;
        case    CF_CALCOP("IsNeg(A)"):
            BignumCalc::AssertBinary(*result, "IsNeg");
            break;
        case    CF_CALCOP("IsNotZero(A)"):
            BignumCalc::AssertBinary(*result, "IsNotZero");
            break;
        case    CF_CALCOP("Cmp(A,B)"):
            BignumCalc::AssertTertiary(*result, "Cmp");
            break;
        case    CF_CALCOP("CmpAbs(A,B)"):
            BignumCalc::AssertTertiary(*result, "CmpAbs");
            break;
        case    CF_CALCOP("Jacobi(A,B)"):
            BignumCalc::AssertTertiary(*result, "Jacobi");
            break;
        case    CF_CALCOP("Sqr(A)"):
            AssertNotSmallerThan(*result, op.bn0, repository::CalcOpToString(calcOp));
            break;
        case    CF_CALCOP("RShift(A,B)"):
            if ( IsZero(op.bn0) || IsZero(op.bn1) ) {
                if ( op.bn0.ToTrimmedString() != result->ToTrimmedString() ) {
                    Abort("Zero operand should not alter input", repository::CalcOpToString(calcOp));
                }
            }

            AssertNotLargerThan(*result, op.bn0, repository::CalcOpToString(calcOp));
            break;
        case    CF_CALCOP("LShift1(A)"):
            if ( IsZero(op.bn0) ) {
                if ( op.bn0.ToTrimmedString() != result->ToTrimmedString() ) {
                    Abort("Zero input should remain zero", repository::CalcOpToString(calcOp));
                }
            }

            AssertNotSmallerThan(*result, op.bn0, repository::CalcOpToString(calcOp));
            break;
        case    CF_CALCOP("SetBit(A,B)"):
            AssertNotSmallerThan(*result, op.bn0, repository::CalcOpToString(calcOp));
            break;
        case    CF_CALCOP("ClearBit(A,B)"):
            AssertNotLargerThan(*result, op.bn0, repository::CalcOpToString(calcOp));
            break;
        case    CF_CALCOP("Sqrt(A)"):
            AssertNotLargerThan(*result, op.bn0, repository::CalcOpToString(calcOp));
            break;
        case    CF_CALCOP("Cbrt(A)"):
            AssertNotLargerThan(*result, op.bn0, repository::CalcOpToString(calcOp));
            break;
        case    CF_CALCOP("MulAdd(A,B,C)"):
            AssertNotSmallerThan(*result, op.bn2, repository::CalcOpToString(calcOp));
            break;
        case    CF_CALCOP("Min(A,B)"):
        case    CF_CALCOP("Max(A,B)"):
            if ( !IsEqual(*result, op.bn0) && !IsEqual(*result, op.bn1) ) {
                Abort("Result is not an operand", repository::CalcOpToString(calcOp));
            }
            break;
        case    CF_CALCOP("Mask(A,B)"):
            if ( LargerThan(*result, op.bn0) ) {
                Abort("Result is larger than input", repository::CalcOpToString(calcOp));
            }
            break;
        case    CF_CALCOP("And(A,B)"):
            AssertNotLargerThan(*result, op.bn0, repository::CalcOpToString(calcOp));
            AssertNotLargerThan(*result, op.bn1, repository::CalcOpToString(calcOp));
            break;
        case    CF_CALCOP("Or(A,B)"):
            AssertNotSmallerThan(*result, op.bn0, repository::CalcOpToString(calcOp));
            AssertNotSmallerThan(*result, op.bn1, repository::CalcOpToString(calcOp));
            break;
        case    CF_CALCOP("Nthrt(A,B)"):
        case    CF_CALCOP("NthrtRem(A,B)"):
            if ( IsZero(op.bn1) ) {
                Abort("Root of zero should not produce a result", repository::CalcOpToString(calcOp));
            }
            break;
        case    CF_CALCOP("Zero()"):
            if ( !IsZero(*result) ) {
                Abort("Result should be zero", repository::CalcOpToString(calcOp));
            }
            break;
        case    CF_CALCOP("GCD(A,B)"):
            AssertNotLargerThan(*result, op.bn0, op.bn1, repository::CalcOpToString(calcOp));
            break;
        case    CF_CALCOP("LCM(A,B)"):
            AssertNotSmallerThan(*result, op.bn0, op.bn1, repository::CalcOpToString(calcOp));
            break;
        case    CF_CALCOP("InvMod(A,B)"):
            if ( !IsZero(*result) ) {
                AssertNotLargerThan(*result, op.bn1, repository::CalcOpToString(calcOp));
            }
            break;
        case    CF_CALCOP("Exp(A,B)"):
            AssertNotSmallerThan(*result, op.bn0, op.bn1, repository::CalcOpToString(calcOp));
            break;
        case    CF_CALCOP("RandMod(A)"):
            BignumCalc::AssertModResult(*result, op.bn0, "RandMod");
            break;
        case    CF_CALCOP("Prime()"):
            BignumCalc::AssertPositive(*result, repository::CalcOpToString(calcOp));
            if ( result->ToTrimmedString() != "2" ) {
                BignumCalc::AssertOdd(*result, repository::CalcOpToString(calcOp));
            }
            break;
        case    CF_CALCOP("RandRange(A,B)"):
            AssertNotLargerThan(*result, op.bn1, repository::CalcOpToString(calcOp));
            break;
    }
}

void test(const operation::BignumCalc_Fp2& op, const std::optional<component::Fp2>& result) {
    (void)op;
    (void)result;
}

void test(const operation::BignumCalc_Fp12& op, const std::optional<component::Fp12>& result) {
    (void)op;
    (void)result;
}