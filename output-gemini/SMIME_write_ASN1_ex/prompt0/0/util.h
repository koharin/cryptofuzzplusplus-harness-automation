std::string ToString(const SMIME_write_ASN1_ex_Pair& val) {
    std::stringstream ss;
    ss << "CMS_flag=" << ToString(val.CMS_flag) << ",";
    ss << "SMIME_flag=" << ToString(val.SMIME_flag) << ",";
    ss << "cipherType=" << ToString(val.cipherType);
    return ss.str();
}
nlohmann::json ToJSON(const SMIME_write_ASN1_ex_Pair& val) {
    nlohmann::json j;
    j["CMS_flag"] = val.CMS_flag;
    j["SMIME_flag"] = val.SMIME_flag;
    j["cipherType"] = val.cipherType;
    return j;
}
