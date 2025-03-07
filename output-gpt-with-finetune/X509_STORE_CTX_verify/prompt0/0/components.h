class X509_STORE_CTX_verify {
    public:
        std::string ntlsa;
        std::string ncert;
        std::string noncheck;
        std::string ntlsa_data;

        X509_STORE_CTX_verify(Datasource& ds) {
            ntlsa = ds.GetString();
            ncert = ds.GetString();
            noncheck = ds.GetString();
            ntlsa_data = ds.GetString();
        }

        X509_STORE_CTX_verify(nlohmann::json json) {
            ntlsa = json["ntlsa"].get<std::string>();
            ncert = json["ncert"].get<std::string>();
            noncheck = json["noncheck"].get<std::string>();
            ntlsa_data = json["ntlsa_data"].get<std::string>();
        }

        bool operator==(const X509_STORE_CTX_verify& rhs) const {
            return (ntlsa == rhs.ntlsa) &&
                   (ncert == rhs.ncert) &&
                   (noncheck == rhs.noncheck) &&
                   (ntlsa_data == rhs.ntlsa_data);
        }

        void Serialize(Datasource& ds) const {
            ds.Put(ntlsa);
            ds.Put(ncert);
            ds.Put(noncheck);
            ds.Put(ntlsa_data);
        }

        nlohmann::json ToJSON(void) const {
            nlohmann::json json;
            json["ntlsa"] = ntlsa;
            json["ncert"] = ncert;
            json["noncheck"] = noncheck;
            json["ntlsa_data"] = ntlsa_data;
            return json;
        }
};
