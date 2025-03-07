class SMIME_write_ASN1_ex : public Operation {
    public:
        const component::Cleartext cleartext;
        const component::CMS_flag CMS_flag;
        const component::SMIME_flag SMIME_flag;
        uint64_t ctype_nid;
        uint64_t econt_nid;
        const component::cipherType cipherType;

        SMIME_write_ASN1_ex(Datasource& ds, component::Modifier modifier) :
            Operation(std::move(modifier)),
            cleartext(ds),
            CMS_flag(ds),
            SMIME_flag(ds),
            ctype_nid(ds.Get<uint64_t>()),
            econt_nid(ds.Get<uint64_t>()),
            cipherType(ds)
        { }
        SMIME_write_ASN1_ex(nlohmann::json json) :
            Operation(json["modifier"]),
            cleartext(json["cleartext"]),
            CMS_flag(json["CMS_flag"]),
            SMIME_flag(json["SMIME_flag"]),
            ctype_nid(json["ctype_nid"].get<uint64_t>()),
            econt_nid(json["econt_nid"].get<uint64_t>()),
            cipherType(json["cipherType"])
        { }

        static size_t MaxOperations(void) { return 20; }
        std::string Name(void) const override;
        std::string ToString(void) const override;
        nlohmann::json ToJSON(void) const override;
        inline bool operator==(const SMIME_write_ASN1_ex& rhs) const {
            return
                (cleartext == rhs.cleartext) &&
                (CMS_flag == rhs.CMS_flag) &&
                (SMIME_flag == rhs.SMIME_flag) &&
                (ctype_nid == rhs.ctype_nid) &&
                (econt_nid == rhs.econt_nid) &&
                (cipherType == rhs.cipherType) &&
                (modifier == rhs.modifier);
        }
        void Serialize(Datasource& ds) const {
            cleartext.Serialize(ds);
            CMS_flag.Serialize(ds);
            SMIME_flag.Serialize(ds);
            ds.Put<>(ctype_nid);
            ds.Put<>(econt_nid);
            cipherType.Serialize(ds);
        }
};
