typedef struct {
    std::vector<uint8_t> ntlsa;
    std::vector<uint8_t> ncert;
    std::vector<uint8_t> noncheck;
} X509_STORE_CTX_verify_Pair;
extern MutatorPool<X509_STORE_CTX_verify_Pair, cryptofuzz::config::kMutatorPoolSize> Pool_X509_STORE_CTX_verify;
