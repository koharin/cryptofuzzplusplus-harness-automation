class SMIME_write_ASN1_ex {
    public:
        BIO *out;
        ASN1_VALUE *val;
        BIO *data;
        int flags;
        int ctype_nid;
        int econt_nid;
        STACK_OF(X509_ALGOR) *mdalgs;
        const ASN1_ITEM *it;
        OSSL_LIB_CTX *libctx;
        const char *propq;

        SMIME_write_ASN1_ex(Datasource& ds) {
            std::vector<uint8_t> _out = ds.Get<std::vector<uint8_t>>();
            std::vector<uint8_t> _val = ds.Get<std::vector<uint8_t>>();
            std::vector<uint8_t> _data = ds.Get<std::vector<uint8_t>>();
            flags = ds.Get<int>();
            ctype_nid = ds.Get<int>();
            econt_nid = ds.Get<int>();
            std::vector<uint8_t> _mdalgs = ds.Get<std::vector<uint8_t>>();
            std::vector<uint8_t> _it = ds.Get<std::vector<uint8_t>>();
            std::vector<uint8_t> _libctx = ds.Get<std::vector<uint8_t>>();
            std::string _propq = ds.Get<std::string>();
        }

        SMIME_write_ASN1_ex(const SMIME_write_ASN1_ex_Pair& pair) {
            flags = pair.CMS_flag | pair.SMIME_flag;
        }
        bool operator==(const SMIME_write_ASN1_ex& rhs) const {
            (void)rhs;
            return false;
        }
        void Serialize(Datasource& ds) const {
            (void)ds;
        }
        nlohmann::json ToJSON(void) const {
            return nlohmann::json();
        }

};
