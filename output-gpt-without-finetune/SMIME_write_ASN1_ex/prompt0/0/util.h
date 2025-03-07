std::string ToString(const SMIME_Encryption_Params& val) {
    std::ostringstream oss;
    oss << "CMS_flag: " << val.CMS_flag << ", "
        << "SMIME_flag: " << val.SMIME_flag << ", "
        << "cipherType: " << val.cipherType;
    return oss.str();
}

nlohmann::json ToJSON(const SMIME_Encryption_Params& val) {
    return nlohmann::json{
        {"CMS_flag", val.CMS_flag},
        {"SMIME_flag", val.SMIME_flag},
        {"cipherType", val.cipherType}
    };
}
