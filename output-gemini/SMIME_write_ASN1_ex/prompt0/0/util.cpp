std::string ToString(const SMIME_write_ASN1_ex_Pair& val) {
    std::string ret;
    ret += "CMS_flag: ";
    ret += std::to_string(val.CMS_flag);
    ret += "\n";
    ret += "SMIME_flag: ";
    ret += std::to_string(val.SMIME_flag);
    ret += "\n";
    ret += "cipherType: ";
    ret += std::to_string(val.cipherType);
    ret += "\n";
    return ret;
}

nlohmann::json ToJSON(const SMIME_write_ASN1_ex_Pair& val) {
    nlohmann::json j;
    j["CMS_flag"] = val.CMS_flag;
    j["SMIME_flag"] = val.SMIME_flag;
    j["cipherType"] = val.cipherType;
    return j;
}
