std::string X509_STORE_CTX_verify::Name(void) const { return "X509_STORE_CTX_verify"; }

std::string X509_STORE_CTX_verify::ToString(void) const {
    std::stringstream ss;

    ss << "operation name: X509_STORE_CTX_verify" << std::endl;
    ss << "ntlsa data: " << util::HexDump(ntlsa_data.Get()) << std::endl;
    ss << "ncert: " << ncert.ToString() << std::endl;
    ss << "noncheck: " << noncheck.ToString() << std::endl;

    return ss.str();
}

nlohmann::json X509_STORE_CTX_verify::ToJSON(void) const {
    nlohmann::json j;
    j["operation"] = "X509_STORE_CTX_verify";
    j["ntlsa_data"] = ntlsa_data.ToJSON();
    j["ncert"] = ncert.ToJSON();
    j["noncheck"] = noncheck.ToJSON();

    j["modifier"] = modifier.ToJSON();
    return j;
}
