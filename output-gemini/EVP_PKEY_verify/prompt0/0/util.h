std::string ToString(const EVP_PKEY_verify_Pair& val) {
    return "cleartext: " + ToString(val.cleartext) + "\n" +
           "digestType: " + ToString(val.digestType) + "\n" +
           "keySize: " + ToString(val.keySize) + "\n" +
           "signature: " + ToString(val.signature);
}

nlohmann::json ToJSON(const EVP_PKEY_verify_Pair& val) {
    nlohmann::json j;
    j["cleartext"] = ToJSON(val.cleartext);
    j["digestType"] = val.digestType;
    j["keySize"] = val.keySize;
    j["signature"] = ToJSON(val.signature);
    return j;
}
