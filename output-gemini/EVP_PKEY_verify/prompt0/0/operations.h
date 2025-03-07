class EVP_PKEY_Verify : public Operation {
    public:
        const component::Cleartext cleartext;
        const component::DigestType digestType;
        const Buffer signature;
        const uint64_t keySize;

        EVP_PKEY_Verify(Datasource& ds, component::Modifier modifier) :
            Operation(std::move(modifier)),
            cleartext(ds),
            digestType(ds),
            signature(ds),
            keySize(ds.Get<uint64_t>() % 4096)
        { }
        EVP_PKEY_Verify(nlohmann::json json) :
            Operation(json["modifier"]),
            cleartext(json["cleartext"]),
            digestType(json["digestType"]),
            signature(json["signature"]),
            keySize(json["keySize"].get<uint64_t>())
        { }

        static size_t MaxOperations(void) { return 5; }
        std::string Name(void) const override;
        std::string ToString(void) const override;
        nlohmann::json ToJSON(void) const override;
        inline bool operator==(const EVP_PKEY_Verify& rhs) const {
            return
                (cleartext == rhs.cleartext) &&
                (digestType == rhs.digestType) &&
                (signature == rhs.signature) &&
                (keySize == rhs.keySize) &&
                (modifier == rhs.modifier);
        }
        void Serialize(Datasource& ds) const {
            cleartext.Serialize(ds);
            digestType.Serialize(ds);
            signature.Serialize(ds);
            ds.Put<>(keySize);
        }
};
