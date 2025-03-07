std::string ToString(const component::CMS_flag& val) {
    return std::to_string(val.value);
}

std::string ToString(const component::SMIME_flag& val) {
    return std::to_string(val.value);
}

std::string ToString(const component::cipherType& val) {
    return std::to_string(val.cipherType);
}
