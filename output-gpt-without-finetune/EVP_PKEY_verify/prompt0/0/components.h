using Cleartext = Buffer;
using DigestType = Type;
using KeySize = size_t;

class EVP_PKEY_verify_Mutation {
    public:
        Cleartext cleartext;
        DigestType digestType;
        KeySize keySize;

        // Constructor from Datasource
        EVP_PKEY_verify_Mutation(Datasource& ds) {
            cleartext = Cleartext(ds);
            digestType = DigestType(ds);
            keySize = ds.Get<KeySize>();
        }

        // Constructor with specific values
        EVP_PKEY_verify_Mutation(Cleartext cleartext, DigestType digestType, KeySize keySize) :
            cleartext(cleartext),
            digestType(digestType),
            keySize(keySize)
        { }

        bool operator==(const EVP_PKEY_verify_Mutation& rhs) const {
            return
                (cleartext == rhs.cleartext) &&
                (digestType == rhs.digestType) &&
                (keySize == rhs.keySize);
        }

        // Serialize to Datasource
        void Serialize(Datasource& ds) const {
            cleartext.Serialize(ds);
            digestType.Serialize(ds);
            ds.Put(keySize);
        }

        // Serialize to JSON
        nlohmann::json ToJSON(void) const {
            return nlohmann::json {
                {"cleartext", cleartext.ToJSON()},
                {"digestType", digestType.ToJSON()},
                {"keySize", keySize}
            };
        }
};
