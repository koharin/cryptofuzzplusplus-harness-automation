std::string ToString(const X509_STORE_CTX_verify_Pair& val) {
    std::string ret;

    ret += "ntlsa: ";
    ret += util::HexDump(val.ntlsa);
    ret += "\n";

    ret += "ncert: ";
    ret += util::HexDump(val.ncert);
    ret += "\n";

    ret += "noncheck: ";
    ret += util::HexDump(val.noncheck);
    ret += "\n";

    return ret;
}

nlohmann::json ToJSON(const X509_STORE_CTX_verify_Pair& val) {
    nlohmann::json ret;

    ret["ntlsa"] = util::HexDump(val.ntlsa);
    ret["ncert"] = util::HexDump(val.ncert);
    ret["noncheck"] = util::HexDump(val.noncheck);

    return ret;
}
