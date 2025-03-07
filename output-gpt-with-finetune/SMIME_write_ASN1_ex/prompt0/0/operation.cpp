std::string SMIME_write_ASN1_ex::Name(void) const { return "SMIME_write_ASN1_ex"; }
std::string SMIME_write_ASN1_ex::ToString(void) const {
    std::stringstream ss;

    ss << "operation name: SMIME_write_ASN1_ex" << std::endl;
    ss << "CMS_flag: " << std::to_string(CMS_flag) << std::endl;
    ss << "SMIME_flag: " << std::to_string(SMIME_flag) << std::endl;
    ss << "cipherType: " << repository::CipherToString(cipherType.Get()) << std::endl;

    return ss.str();
}

nlohmann::json SMIME_write_ASN1_ex::ToJSON(void) const {
    nlohmann::json j;
    j["operation"] = "SMIME_write_ASN1_ex";
    j["CMS_flag"] = CMS_flag;
    j["SMIME_flag"] = SMIME_flag;
    j["cipherType"] = cipherType.ToJSON();
    j["modifier"] = modifier.ToJSON();
    return j;
}
