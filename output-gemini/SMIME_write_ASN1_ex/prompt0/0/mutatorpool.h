typedef struct {
    int CMS_flag;
    int SMIME_flag;
    int cipherType;
} SMIME_write_ASN1_ex_Pair;
extern MutatorPool<SMIME_write_ASN1_ex_Pair, cryptofuzz::config::kMutatorPoolSize> Pool_SMIME_write_ASN1_ex;
