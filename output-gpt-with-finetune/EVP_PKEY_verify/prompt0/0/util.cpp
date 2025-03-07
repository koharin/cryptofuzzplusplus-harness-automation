std::string ToString(const EVP_PKEY_verify& val) {
    std::string ret;

    ret += "Cleartext: ";
    ret += val.cleartext;
    ret += "\n";

    ret += "Digest Type: ";
    ret += val.digestType;
    ret += "\n";

    ret += "Key Size: ";
    ret += std::to_string(val.keySize);
    ret += "\n";

    return ret;
}

nlohmann::json ToJSON(const EVP_PKEY_verify& val) {
    nlohmann::json ret;

    ret["cleartext"] = val.cleartext;
    ret["digestType"] = val.digestType;
    ret["keySize"] = val.keySize;

    return ret;
}
