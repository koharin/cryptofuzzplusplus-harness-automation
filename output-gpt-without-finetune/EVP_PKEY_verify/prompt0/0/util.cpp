std::string ToString(const EVP_PKEY_verify_Mutation& mutation) {
    std::string ret;

    ret += "Cleartext: " + mutation.cleartext + "\n";
    ret += "Digest Type: " + mutation.digestType + "\n";
    ret += "Key Size: " + std::to_string(mutation.keySize) + "\n";

    return ret;
}

nlohmann::json ToJSON(const EVP_PKEY_verify_Mutation& mutation) {
    nlohmann::json ret;

    ret["cleartext"] = mutation.cleartext;
    ret["digestType"] = mutation.digestType;
    ret["keySize"] = mutation.keySize;

    return ret;
}
