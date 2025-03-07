std::string EVP_PKEY_Verify::Name(void) const { return "EVP_PKEY_Verify"; }
std::string EVP_PKEY_Verify::ToString(void) const {
    std::stringstream ss;

    ss << "operation name: EVP_PKEY_Verify" << std::endl;
    ss << "digest: " << repository::DigestToString(digestType.Get()) << std::endl;
    ss << "cleartext: " << util::HexDump(cleartext.Get()) << std::endl;
    ss << "keySize: " << std::to_string(keySize) << std::endl;

    return ss.str();
}

nlohmann::json EVP_PKEY_Verify::ToJSON(void) const {
    nlohmann::json j;
    j["operation"] = "EVP_PKEY_Verify";
    j["digestType"] = digestType.ToJSON();
    j["cleartext"] = cleartext.ToJSON();
    j["keySize"] = keySize;
    j["modifier"] = modifier.ToJSON();
    return j;
}
