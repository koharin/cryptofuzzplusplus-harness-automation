class EVP_PKEY_verify : public Operation {
    public:
        const component::Cleartext cleartext;
        const component::DigestType digestType;
        const uint64_t keySize;

        EVP_PKEY_verify(Datasource& ds, component::Modifier modifier) :
            Operation(std::move(modifier)),
            cleartext(ds),
            digestType(ds),
            keySize(ds.Get<uint64_t>() % 1024)
        { }
        EVP_PKEY_verify(nlohmann::json json) :
            Operation(json["modifier"]),
            cleartext(json["cleartext"]),
            digestType(json["digestType"]),
            keySize(json["keySize"].get<uint64_t>())
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
            ds.Put<>(keySize);
        }
};
