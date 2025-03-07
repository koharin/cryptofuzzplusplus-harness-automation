/* X509_STORE_CTX_verify */

X509_STORE_CTX_verify_Pair::X509_STORE_CTX_verify_Pair(Datasource& ds) {
    ntlsa = ds.GetData(0, 0, (10*1024*1024));
    ncert = ds.GetData(0, 0, (10*1024*1024));
    noncheck = ds.GetData(0, 0, (10*1024*1024));
}

X509_STORE_CTX_verify_Pair::X509_STORE_CTX_verify_Pair(const X509_STORE_CTX_verify_Pair& other) :
    ntlsa(other.ntlsa),
    ncert(other.ncert),
    noncheck(other.noncheck)
{ }

X509_STORE_CTX_verify_Pair::X509_STORE_CTX_verify_Pair(nlohmann::json json) :
    ntlsa(json["ntlsa"].get<std::string>()),
    ncert(json["ncert"].get<std::string>()),
    noncheck(json["noncheck"].get<std::string>())
{ }

nlohmann::json X509_STORE_CTX_verify_Pair::ToJSON(void) const {
    nlohmann::json j;
    j["ntlsa"] = ntlsa;
    j["ncert"] = ncert;
    j["noncheck"] = noncheck;
    return j;
}

bool X509_STORE_CTX_verify_Pair::operator==(const X509_STORE_CTX_verify_Pair& rhs) const {
    return
        (ntlsa == rhs.ntlsa) &&
        (ncert == rhs.ncert) &&
        (noncheck == rhs.noncheck);
}

void X509_STORE_CTX_verify_Pair::Serialize(Datasource& ds) const {
    ds.PutData(ntlsa);
    ds.PutData(ncert);
    ds.PutData(noncheck);
}

std::vector<uint8_t> X509_STORE_CTX_verify_Pair::GetInputData(void) const {
    std::vector<uint8_t> ret;
    ret.insert(ret.end(), ntlsa.begin(), ntlsa.end());
    ret.insert(ret.end(), ncert.begin(), ncert.end());
    ret.insert(ret.end(), noncheck.begin(), noncheck.end());
    return ret;
}

void X509_STORE_CTX_verify_Pair::Mutate(Datasource& ds, size_t mutationIndex) {
    switch (mutationIndex) {
        case 0:
        {
            /* Flip random bits in ntlsa_data */
            if ( ntlsa.size() ) {
                auto num = ds.Get<uint64_t>();
                for (size_t i = 0; i < num; i++) {
                    const size_t offset = ds.Get<size_t>() % ntlsa.size();
                    const uint8_t bit = ds.Get<uint8_t>() % 8;
                    ntlsa[offset] ^= 1 << bit;
                }
            }
            break;
        }
        default:
            /* Other mutation cases can be added here */
            break;
    }
}
