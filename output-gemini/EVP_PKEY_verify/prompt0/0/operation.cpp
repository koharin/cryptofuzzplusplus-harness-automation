std::string EVP_PKEY_verify::Name(void) const { return "EVP_PKEY_verify"; }
std::string EVP_PKEY_verify::ToString(void) const {
    std::stringstream ss;

    ss << "operation name: EVP_PKEY_verify" << std::endl;
    ss << "cleartext: " << util::HexDump(cleartext.Get()) << std::endl;
    ss << "digest: " << repository::DigestToString(digestType.Get()) << std::endl;
    ss << "key size: " << keySize << std::endl;

    return ss.str();
}

nlohmann::json EVP_PKEY_verify::ToJSON(void) const {
    nlohmann::json j;
    j["operation"] = "EVP_PKEY_verify";
    j["cleartext"] = cleartext.ToJSON();
    j["digestType"] = digestType.ToJSON();
    j["keySize"] = keySize;
    j["modifier"] = modifier.ToJSON();
    return j;
}
