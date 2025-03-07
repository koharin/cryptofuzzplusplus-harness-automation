/* EVP_PKEY_verify */

EVP_PKEY_verify_Pair::EVP_PKEY_verify_Pair(Datasource& ds) :
    cleartext(ds),
    digestType(ds.Get<uint64_t>()),
    keySize(ds.Get<uint64_t>()),
    signature(ds)
{ }

EVP_PKEY_verify_Pair::EVP_PKEY_verify_Pair(const EVP_PKEY_verify_Pair& other) :
    cleartext(other.cleartext),
    digestType(other.digestType),
    keySize(other.keySize),
    signature(other.signature)
{ }

EVP_PKEY_verify_Pair::EVP_PKEY_verify_Pair(nlohmann::json json) :
    cleartext(json["cleartext"].get<std::string>()),
    digestType(json["digestType"].get<uint64_t>()),
    keySize(json["keySize"].get<uint64_t>()),
    signature(json["signature"].get<std::string>())
{ }

bool EVP_PKEY_verify_Pair::operator==(const EVP_PKEY_verify_Pair& rhs) const {
    return
        (cleartext == rhs.cleartext) &&
        (digestType == rhs.digestType) &&
        (keySize == rhs.keySize) &&
        (signature == rhs.signature);
}

void EVP_PKEY_verify_Pair::Serialize(Datasource& ds) const {
    ds.Put<std::string>(cleartext);
    ds.Put<>(digestType);
    ds.Put<>(keySize);
    ds.Put<std::string>(signature);
}

nlohmann::json EVP_PKEY_verify_Pair::ToJSON(void) const {
    nlohmann::json j;
    j["cleartext"] = cleartext;
    j["digestType"] = digestType;
    j["keySize"] = keySize;
    j["signature"] = signature;
    return j;
}