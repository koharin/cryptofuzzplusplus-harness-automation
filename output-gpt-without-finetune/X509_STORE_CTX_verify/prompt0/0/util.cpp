std::string ToString(const X509_STORE_CTX_verify_Mutation& val) {
    std::string ret;

    ret += "ntlsa: ";
    ret += val.ntlsa;
    ret += "\n";

    ret += "ncert: ";
    ret += val.ncert;
    ret += "\n";

    ret += "noncheck: ";
    ret += val.noncheck;
    ret += "\n";

    ret += "ntlsa_data: ";
    ret += util::HexDump(val.ntlsa_data, strlen(reinterpret_cast<const char*>(val.ntlsa_data)), "ntlsa_data");
    ret += "\n";

    return ret;
}

nlohmann::json ToJSON(const X509_STORE_CTX_verify_Mutation& val) {
    nlohmann::json ret;

    ret["ntlsa"] = val.ntlsa;
    ret["ncert"] = val.ncert;
    ret["noncheck"] = val.noncheck;
    ret["ntlsa_data"] = util::HexDump(val.ntlsa_data, strlen(reinterpret_cast<const char*>(val.ntlsa_data)), "ntlsa_data");

    return ret;
}
