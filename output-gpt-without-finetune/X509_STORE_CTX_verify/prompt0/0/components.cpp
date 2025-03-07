class X509_STORE_CTX_Verify {
private:
    Buffer ntlsa;
    Buffer ncert;
    Buffer noncheck;
    const uint8_t* ntlsa_data;
public:
    X509_STORE_CTX_Verify(Datasource& ds) :
        ntlsa(ds),
        ncert(ds),
        noncheck(ds),
        ntlsa_data(ds.GetDataPtr())
    { }

    X509_STORE_CTX_Verify(const X509_STORE_CTX_Verify& other) :
        ntlsa(other.ntlsa),
        ncert(other.ncert),
        noncheck(other.noncheck),
        ntlsa_data(other.ntlsa_data)
    { }

    X509_STORE_CTX_Verify(nlohmann::json json) :
        ntlsa(json["ntlsa"]),
        ncert(json["ncert"]),
        noncheck(json["noncheck"]),
        ntlsa_data(nullptr) // Assume deserialization from JSON does not provide a data pointer directly
    { }

    bool operator==(const X509_STORE_CTX_Verify& rhs) const {
        return
            (ntlsa == rhs.ntlsa) &&
            (ncert == rhs.ncert) &&
            (noncheck == rhs.noncheck);
    }

    nlohmann::json ToJSON(void) const {
        nlohmann::json j;
        j["ntlsa"] = ntlsa.ToJSON();
        j["ncert"] = ncert.ToJSON();
        j["noncheck"] = noncheck.ToJSON();
        // Note: ntlsa_data is not included in JSON conversion
        return j;
    }

    void Serialize(Datasource& ds) const {
        ntlsa.Serialize(ds);
        ncert.Serialize(ds);
        noncheck.Serialize(ds);
        // Note: ntlsa_data serialization would depend on how it's used/stored
    }
};
