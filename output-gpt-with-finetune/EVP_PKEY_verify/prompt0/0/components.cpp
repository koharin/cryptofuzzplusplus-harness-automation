/* EVP_PKEY_verify */

EVP_PKEY_verify::EVP_PKEY_verify(Datasource& ds) :
    cleartext(ds),
    digestType(ds) {
    keySize = ds.Get<size_t>();
}

EVP_PKEY_verify::EVP_PKEY_verify(nlohmann::json json) :
    cleartext(json["cleartext"]),
    digestType(json["digestType"]) {
    keySize = json["keySize"];
}

bool EVP_PKEY_verify::operator==(const EVP_PKEY_verify& rhs) const {
    return
        (cleartext == rhs.cleartext) &&
        (digestType == rhs.digestType) &&
        (keySize == rhs.keySize);
}

void EVP_PKEY_verify::Serialize(Datasource& ds) const {
    cleartext.Serialize(ds);
    digestType.Serialize(ds);
    ds.Put<>(keySize);
}

nlohmann::json EVP_PKEY_verify::ToJSON(void) const {
    nlohmann::json j;
    j["cleartext"] = cleartext.ToJSON();
    j["digestType"] = digestType.ToJSON();
    j["keySize"] = keySize;
    return j;
}
