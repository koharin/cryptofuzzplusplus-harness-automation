std::string SMIME_write_ASN1_ex::Name(void) const { return "SMIME_write_ASN1_ex"; }
std::string SMIME_write_ASN1_ex::ToString(void) const {
    std::stringstream ss;

    ss << "operation name: SMIME_write_ASN1_ex" << std::endl;
    ss << "value: " << value << std::endl;
    ss << "data: " << util::HexDump(data.Get()) << std::endl;
    ss << "flags: " << std::to_string(flags) << std::endl;
    ss << "ctype_nid: " << std::to_string(ctype_nid) << std::endl;
    ss << "econt_nid: " << std::to_string(econt_nid) << std::endl;
    ss << "mdalgs: " << util::HexDump((const uint8_t*)mdalgs) << std::endl; /* TODO */
    ss << "it: " << util::HexDump((const uint8_t*)it) << std::endl; /* TODO */
    ss << "cipher: " << repository::CipherToString(cipherType.Get()) << std::endl;
    ss << "CMS_flag: " << CMS_flag << std::endl;
    ss << "SMIME_flag: " << SMIME_flag << std::endl;

    return ss.str();
}

nlohmann::json SMIME_write_ASN1_ex::ToJSON(void) const {
    nlohmann::json j;
    j["operation"] = "SMIME_write_ASN1_ex";
    j["value"] = value; /* TODO */
    j["data"] = data.ToJSON();
    j["flags"] = flags;
    j["ctype_nid"] = ctype_nid;
    j["econt_nid"] = econt_nid;
    j["mdalgs"] = mdalgs; /* TODO */
    j["it"] = it; /* TODO */
    j["cipherType"] = cipherType.ToJSON();
    j["CMS_flag"] = CMS_flag;
    j["SMIME_flag"] = SMIME_flag;
    j["modifier"] = modifier.ToJSON();
    return j;
}