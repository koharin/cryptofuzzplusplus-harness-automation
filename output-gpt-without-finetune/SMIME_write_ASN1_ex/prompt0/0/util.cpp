std::string ToString(const SMIME_Encryption_Params& params) {
    std::string ret;

    ret += "CMS_flag: " + std::to_string(params.CMS_flag) + "\n";
    ret += "SMIME_flag: " + std::to_string(params.SMIME_flag) + "\n";
    ret += "cipherType: " + std::to_string(params.cipherType) + "\n";

    return ret;
}

nlohmann::json ToJSON(const SMIME_Encryption_Params& params) {
    nlohmann::json ret;

    ret["CMS_flag"] = params.CMS_flag;
    ret["SMIME_flag"] = params.SMIME_flag;
    ret["cipherType"] = params.cipherType;

    return ret;
}
