std::string SMIME_Write_ASN1_Ex::Name(void) const { return "SMIME_Write_ASN1_Ex"; }

std::string SMIME_Write_ASN1_Ex::ToString(void) const {
    std::stringstream ss;

    ss << "operation name: SMIME_Write_ASN1_Ex" << std::endl;
    ss << "CMS_flag: " << std::to_string(CMS_flag) << std::endl;
    ss << "SMIME_flag: " << std::to_string(SMIME_flag) << std::endl;
    ss << "cipherType: " << repository::CipherToString(cipherType.Get()) << std::endl;

    return ss.str();
}

nlohmann::json SMIME_Write_ASN1_Ex::ToJSON(void) const {
    nlohmann::json j;
    j["operation"] = "SMIME_Write_ASN1_Ex";
    j["CMS_flag"] = CMS_flag;
    j["SMIME_flag"] = SMIME_flag;
    j["cipherType"] = cipherType.ToJSON();
    j["modifier"] = modifier.ToJSON();
    return j;
}
