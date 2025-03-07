class X509_Store_CTX_Verify {
    public:
        std::string ntlsa;
        std::string ncert;
        std::string noncheck;

        const uint8_t* ntlsa_data;

        // Constructor from Datasource for deserialization
        X509_Store_CTX_Verify(Datasource& ds) {
            ntlsa = ds.Get<std::string>();
            ncert = ds.Get<std::string>();
            noncheck = ds.Get<std::string>();
            ntlsa_data = reinterpret_cast<const uint8_t*>(ntlsa.data());
        }

        // Constructor using specific values
        X509_Store_CTX_Verify(const std::string& ntlsa, const std::string& ncert, const std::string& noncheck, const uint8_t* ntlsa_data)
            : ntlsa(ntlsa), ncert(ncert), noncheck(noncheck), ntlsa_data(ntlsa_data) {}

        // Deserialize from JSON
        X509_Store_CTX_Verify(nlohmann::json json)
            : ntlsa(json["ntlsa"]), ncert(json["ncert"]), noncheck(json["noncheck"]) {
            ntlsa_data = reinterpret_cast<const uint8_t*>(ntlsa.data());
        }

        inline bool operator==(const X509_Store_CTX_Verify& rhs) const {
            return 
                ntlsa == rhs.ntlsa &&
                ncert == rhs.ncert &&
                noncheck == rhs.noncheck &&
                std::memcmp(ntlsa_data, rhs.ntlsa_data, ntlsa.size()) == 0;
        }
        
        void Serialize(Datasource& ds) const {
            ds.Put(ntlsa);
            ds.Put(ncert);
            ds.Put(noncheck);
        }

        nlohmann::json ToJSON(void) const {
            return nlohmann::json{
                {"ntlsa", ntlsa},
                {"ncert", ncert},
                {"noncheck", noncheck}
            };
        }
};
