class SMIME_write_ASN1 : public Operation {
    public:
        const component::Type type;
        const component::Cleartext cleartext;
        const component::CMS_flag CMS_flags;
        const component::SMIME_flag SMIME_flags;
        const component::CipherType cipherType;
        const component::Bignum serial;
        const component::Bignum version;
        /* TODO: How to represent STACK_OF(X509_ALGOR) *mdalgs ? */

        SMIME_write_ASN1(Datasource& ds, component::Modifier modifier) :
            Operation(std::move(modifier)),
            type(ds),
            cleartext(ds),
            CMS_flags(ds),
            SMIME_flags(ds),
            cipherType(ds),
            serial(ds),
            version(ds)
        { }
        SMIME_write_ASN1(nlohmann::json json) :
            Operation(json["modifier"]),
            type(json["type"]),
            cleartext(json["cleartext"]),
            CMS_flags(json["CMS_flags"]),
            SMIME_flags(json["SMIME_flags"]),
            cipherType(json["cipherType"]),
            serial(json["serial"]),
            version(json["version"])
        { }

        static size_t MaxOperations(void) { return 5; }
        std::string Name(void) const override;
        std::string ToString(void) const override;
        nlohmann::json ToJSON(void) const override;
        inline bool operator==(const SMIME_write_ASN1& rhs) const {
            return
                (type == rhs.type) &&
                (cleartext == rhs.cleartext) &&
                (CMS_flags == rhs.CMS_flags) &&
                (SMIME_flags == rhs.SMIME_flags) &&
                (cipherType == rhs.cipherType) &&
                (serial == rhs.serial) &&
                (version == rhs.version) &&
                (modifier == rhs.modifier);
        }
        void Serialize(Datasource& ds) const {
            type.Serialize(ds);
            cleartext.Serialize(ds);
            CMS_flags.Serialize(ds);
            SMIME_flags.Serialize(ds);
            cipherType.Serialize(ds);
            serial.Serialize(ds);
            version.Serialize(ds);
        }
};
