class X509_STORE_CTX_verify : public Operation {
    public:
        const std::vector<uint8_t> ntlsa;
        const std::vector<uint8_t> ncert;
        const std::vector<uint8_t> noncheck;

        X509_STORE_CTX_verify(Datasource& ds, component::Modifier modifier) :
            Operation(std::move(modifier)),
            ntlsa(ds),
            ncert(ds),
            noncheck(ds)
        { }

        X509_STORE_CTX_verify(nlohmann::json json) :
            Operation(json["modifier"]),
            ntlsa(json["ntlsa"]),
            ncert(json["ncert"]),
            noncheck(json["noncheck"])
        { }

        static size_t MaxOperations(void) { return 5; }
        std::string Name(void) const override;
        std::string ToString(void) const override;
        nlohmann::json ToJSON(void) const override;
        inline bool operator==(const X509_STORE_CTX_verify& rhs) const {
            return
                (ntlsa == rhs.ntlsa) &&
                (ncert == rhs.ncert) &&
                (noncheck == rhs.noncheck) &&
                (modifier == rhs.modifier);
        }
        void Serialize(Datasource& ds) const {
            ds.Put<>(ntlsa);
            ds.Put<>(ncert);
            ds.Put<>(noncheck);
        }
};

