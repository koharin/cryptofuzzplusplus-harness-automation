class X509_STORE_CTX_Verify : public Operation {
    public:
        const std::vector<component::Certificate> ntlsa; // Trust anchor certificates
        const std::vector<component::Certificate> ncert; // Non-trusted certificates for chain
        const component::HexFlag noncheck; // Verification flags

        X509_STORE_CTX_Verify(Datasource& ds, component::Modifier modifier) :
            Operation(std::move(modifier)),
            ntlsa(ds.Get<component::Certificate>(), ds.Get<component::Certificate>(), ds.Get<component::Certificate>()),
            ncert(ds.Get<component::Certificate>(), ds.Get<component::Certificate>(), ds.Get<component::Certificate>()),
            noncheck(ds)
        { }
        X509_STORE_CTX_Verify(nlohmann::json json) :
            Operation(json["modifier"]),
            ntlsa(json["ntlsa"]),
            ncert(json["ncert"]),
            noncheck(json["noncheck"])
        { }

        static size_t MaxOperations(void) { return 5; }
        std::string Name(void) const override;
        std::string ToString(void) const override;
        nlohmann::json ToJSON(void) const override;
        inline bool operator==(const X509_STORE_CTX_Verify& rhs) const {
            return
                (ntlsa == rhs.ntlsa) &&
                (ncert == rhs.ncert) &&
                (noncheck == rhs.noncheck) &&
                (modifier == rhs.modifier);
        }
        void Serialize(Datasource& ds) const {
            for (const auto& cert : ntlsa) {
                cert.Serialize(ds);
            }
            for (const auto& cert : ncert) {
                cert.Serialize(ds);
            }
            noncheck.Serialize(ds);
        }
};
