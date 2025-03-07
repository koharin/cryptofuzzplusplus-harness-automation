nlohmann::json ToJSON(const X509_STORE_CTX_verify_Pair& val) {
    nlohmann::json j;
    j["ntlsa"] = ToJSON(val.ntlsa);
    j["ncert"] = ToJSON(val.ncert);
    j["noncheck"] = ToJSON(val.noncheck);
    return j;
}
