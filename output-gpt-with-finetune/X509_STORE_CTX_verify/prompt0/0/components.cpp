/* X509_STORE_CTX_verify */

X509_STORE_CTX_verify::X509_STORE_CTX_verify(Datasource& ds) :
    ntlsa(ds),
    ncert(ds),
    noncheck(ds),
    ntlsa_data(ds)
{ }

bool X509_STORE_CTX_verify::operator==(const X509_STORE_CTX_verify& rhs) const {
    return
        (ntlsa == rhs.ntlsa) &&
        (ncert == rhs.ncert) &&
        (noncheck == rhs.noncheck) &&
        (ntlsa_data == rhs.ntlsa_data);
}

void X509_STORE_CTX_verify::Serialize(Datasource& ds) const {
    ntlsa.Serialize(ds);
    ncert.Serialize(ds);
    noncheck.Serialize(ds);
    ntlsa_data.Serialize(ds);
}

nlohmann::json X509_STORE_CTX_verify::ToJSON(void) const {
    nlohmann::json j;
    j["ntlsa"] = ntlsa.ToJSON();
    j["ncert"] = ncert.ToJSON();
    j["noncheck"] = noncheck.ToJSON();
    j["ntlsa_data"] = ntlsa_data.ToJSON();
    return j;
}
