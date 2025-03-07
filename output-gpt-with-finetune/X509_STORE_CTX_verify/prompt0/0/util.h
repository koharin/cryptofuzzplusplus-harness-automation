std::string ToString(const operation::X509_STORE_CTX_verify& op) {
    std::stringstream ss;

    ss << "X509_STORE_CTX_verify(";
    ss << "ntlsa=" << ToString(op.ntlsa) << ", ";
    ss << "ncert=" << ToString(op.ncert) << ", ";
    ss << "noncheck=" << ToString(op.noncheck) << ", ";
    ss << "ntlsa_data=" << ToString(op.ntlsa_data) << ", ";
    ss << ")";

    return ss.str();
}
