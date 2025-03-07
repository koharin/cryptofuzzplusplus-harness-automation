std::string ToString(const operation::EVP_PKEY_verify& op) {
    std::stringstream ss;

    ss << "cleartext=" << ToString(op.cleartext) << std::endl;
    ss << "digestType=" << ToString(op.digestType) << std::endl;
    ss << "keySize=" << std::to_string(op.keySize) << std::endl;

    return ss.str();
}

nlohmann::json ToJSON(const operation::EVP_PKEY_verify& op) {
    nlohmann::json json;

    json["cleartext"] = ToJSON(op.cleartext);
    json["digestType"] = ToJSON(op.digestType);
    json["keySize"] = op.keySize;

    return json;
}
