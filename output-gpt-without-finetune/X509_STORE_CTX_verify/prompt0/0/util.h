std::string ToString(const X509_STORE_CTX_verify_Mutation& mutation) {
    return "NTLSA: " + mutation.ntlsa + ", NCERT: " + mutation.ncert + ", NONCHECK: " + mutation.noncheck;
}

nlohmann::json ToJSON(const X509_STORE_CTX_verify_Mutation& mutation) {
    nlohmann::json json;
    json["ntlsa"] = mutation.ntlsa;
    json["ncert"] = mutation.ncert;
    json["noncheck"] = mutation.noncheck;
    return json;
}
