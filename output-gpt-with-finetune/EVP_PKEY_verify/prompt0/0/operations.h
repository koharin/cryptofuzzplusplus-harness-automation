class EVP_PKEY_verify : public Operation {
    public:
        const component::Cleartext cleartext;
        const component::Cleartext digestType;
        const component::Cleartext keySize;

        EVP_PKEY_verify(Datasource& ds, component::Modifier modifier) :
            Operation(std::move(modifier)),
            cleartext(ds),
            digestType(ds),
            keySize(ds)
        { }
        EVP_PKEY_verify(nlohmann::json json) :
            Operation(json["modifier"]),
            cleartext(json["cleartext"]),
            digestType(json["digestType"]),
            keySize(json["keySize"])
        { }

        static size_t MaxOperations(void) { return 5; }
        std::string Name(void) const override;
        std::string ToString(void) const override;
        nlohmann::json ToJSON(void) const override;
        inline bool operator==(const EVP_PKEY_verify& rhs) const {
            return
                (cleartext == rhs.cleartext) &&
                (digestType == rhs.digestType) &&
                (keySize == rhs.keySize) &&
                (modifier == rhs.modifier);
        }
        void Serialize(Datasource& ds) const {
            cleartext.Serialize(ds);
            digestType.Serialize(ds);
            keySize.Serialize(ds);
        }
};
