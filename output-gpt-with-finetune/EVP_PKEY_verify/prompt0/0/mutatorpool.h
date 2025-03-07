typedef struct {
    std::string cleartext;
    std::string digestType;
    size_t keySize;
} EVP_PKEY_verify;
extern MutatorPool<EVP_PKEY_verify, cryptofuzz::config::kMutatorPoolSize> Pool_EVP_PKEY_verify;
