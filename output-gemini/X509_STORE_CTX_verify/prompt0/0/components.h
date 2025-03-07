class X509_STORE_CTX_verify_Pair {
    public:
        std::vector<uint8_t> ntlsa;
        std::vector<uint8_t> ncert;
        std::vector<uint8_t> noncheck;

        X509_STORE_CTX_verify_Pair(Datasource& ds) {
            ntlsa = ds.Get<std::vector<uint8_t>>();
            ncert = ds.Get<std::vector<uint8_t>>();
            noncheck = ds.Get<std::vector<uint8_t>>();
        }

        X509_STORE_CTX_verify_Pair(const std::vector<uint8_t>& ntlsa, const std::vector<uint8_t>& ncert, const std::vector<uint8_t>& noncheck) :
            ntlsa(ntlsa),
            ncert(ncert),
            noncheck(noncheck)
        { }

        inline bool operator==(const X509_STORE_CTX_verify_Pair& rhs) const {
            return
                (ntlsa == rhs.ntlsa) &&
                (ncert == rhs.ncert) &&
                (noncheck == rhs.noncheck);
        }

        void Serialize(Datasource& ds) const {
            ds.Put(ntlsa);
            ds.Put(ncert);
            ds.Put(noncheck);
        }

        nlohmann::json ToJSON() const {
            nlohmann::json j;
            j["ntlsa"] = ntlsa;
            j["ncert"] = ncert;
            j["noncheck"] = noncheck;
            return j;
        }
};

extern MutatorPool<X509_STORE_CTX_verify_Pair, cryptofuzz::config::kMutatorPoolSize> Pool_X509_STORE_CTX_verify;
