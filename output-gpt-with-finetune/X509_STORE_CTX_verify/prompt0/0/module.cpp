std::optional<int> OpenSSL::OpX509_STORE_CTX_verify(operation::X509_STORE_CTX_verify& op) {
    std::optional<int> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    const unsigned char *p = op.ntlsa_data.c_str();
    X509* cert = nullptr;
    X509_STORE* store = nullptr;

    CF_CHECK_NE(store = X509_STORE_new(), nullptr);

    /* ntlsa_data를 사용하여 인증서 추가 */
    /* DER 형식의 인증서로 가정하고, 하나의 인증서만 추가 */
    CF_CHECK_NE(cert = d2i_X509(nullptr, &p, op.ntlsa_data.size()), nullptr);
    X509_STORE_add_cert(store, cert);
    X509_free(cert);

end:
    if (store != nullptr) {
        X509_STORE_free(store);
    }

    return ret;
}


