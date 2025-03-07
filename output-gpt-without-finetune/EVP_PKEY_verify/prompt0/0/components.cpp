#include <string>
#include "cryptofuzz/config.h"
#include <nlohmann/json.hpp>

struct EVP_PKEY_verify_Mutation {
    std::string cleartext;
    std::string digestType;
    size_t keySize;

    EVP_PKEY_verify_Mutation(Datasource& ds) :
        cleartext(ds.GetString(0, 1024)),
        digestType(ds.GetString(0, 64)),
        keySize(ds.Get<size_t>())
    { }

    EVP_PKEY_verify_Mutation(const EVP_PKEY_verify_Mutation& other) :
        cleartext(other.cleartext),
        digestType(other.digestType),
        keySize(other.keySize)
    { }

    EVP_PKEY_verify_Mutation(nlohmann::json json) :
        cleartext(json["cleartext"].get<std::string>()),
        digestType(json["digestType"].get<std::string>()),
        keySize(json["keySize"].get<size_t>())
    { }

    bool operator==(const EVP_PKEY_verify_Mutation& rhs) const {
        return 
            (cleartext == rhs.cleartext) &&
            (digestType == rhs.digestType) &&
            (keySize == rhs.keySize);
    }

    nlohmann::json ToJSON(void) const {
        nlohmann::json j;
        j["cleartext"] = cleartext;
        j["digestType"] = digestType;
        j["keySize"] = keySize;
        return j;
    }

    void Serialize(Datasource& ds) const {
        ds.PutString(cleartext);
        ds.PutString(digestType);
        ds.Put<>(keySize);
    }
};
