std::string ToString(const EVP_PKEY_verify_Pair& val) {
    std::string ret;

    ret += "cleartext: ";
    ret += ToString(val.cleartext);
    ret += "\n";

    ret += "digestType: ";
    ret += ToString(val.digestType);
    ret += "\n";

    ret += "keySize: ";
    ret += ToString(val.keySize);
    ret += "\n";

    ret += "signature: ";
    ret += ToString(val.signature);
    ret += "\n";

    return ret;
}

nlohmann::json ToJSON(const EVP_PKEY_verify_Pair& val) {
    nlohmann::json ret;

    ret["cleartext"] = val.cleartext;
    ret["digestType"] = val.digestType;
    ret["keySize"] = val.keySize;
    ret["signature"] = val.signature;

    return ret;
}
