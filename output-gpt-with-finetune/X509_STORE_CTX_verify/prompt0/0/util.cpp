std::string ToString(const std::string& ntlsa) {
    return util::HexDump(ntlsa.GetPtr(), ntlsa.GetSize());
}

std::string ToString(const std::string& ncert) {
    return util::HexDump(ncert.GetPtr(), ncert.GetPtr());
}

std::string ToString(const std::string& noncheck) {
    return util::HexDump(noncheck.GetPtr(), noncheck.GetPtr());
}

std::string ToString(const std::string& ntlsa_data) {
    return util::HexDump(ntlsa_data.GetPtr(), ntlsa_data.GetPtr());
}

nlohmann::json ToJSON(const std::string& ntlsa) {
    return ntlsa.ToJSON();
}

nlohmann::json ToJSON(const std::string& ncert) {
    return ncert.ToJSON();
}

nlohmann::json ToJSON(const std::string& noncheck) {
    return noncheck.ToJSON();
}

nlohmann::json ToJSON(const std::string& ntlsa_data) {
    return ntlsa_data.ToJSON();
}
