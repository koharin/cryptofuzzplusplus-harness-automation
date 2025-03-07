typedef struct {
    std::string cleartext;
    uint64_t digestType;
    uint64_t keySize;
    std::string signature;
} EVP_PKEY_verify_Pair;
extern MutatorPool<EVP_PKEY_verify_Pair, cryptofuzz::config::kMutatorPoolSize> Pool_EVP_PKEY_verify;
