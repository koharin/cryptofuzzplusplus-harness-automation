/* SMIME_write_ASN1_ex */

SMIME_write_ASN1_ex::SMIME_write_ASN1_ex(Datasource& ds) :
    bioOut(ds),
    asn1Value(ds),
    bioData(ds),
    flags(ds.Get<uint64_t>()),
    ctypeNid(ds.Get<int32_t>()),
    econtNid(ds.Get<int32_t>()),
    mdalgs(ds),
    it(ds.Get<uint64_t>()),
    libctx(ds),
    propq(ds)
{ }

SMIME_write_ASN1_ex::SMIME_write_ASN1_ex(const SMIME_write_ASN1_ex& other) :
    bioOut(other.bioOut),
    asn1Value(other.asn1Value),
    bioData(other.bioData),
    flags(other.flags),
    ctypeNid(other.ctypeNid),
    econtNid(other.econtNid),
    mdalgs(other.mdalgs),
    it(other.it),
    libctx(other.libctx),
    propq(other.propq)
{ }

SMIME_write_ASN1_ex::SMIME_write_ASN1_ex(nlohmann::json json) :
    bioOut(json["bioOut"]),
    asn1Value(json["asn1Value"]),
    bioData(json["bioData"]),
    flags(json["flags"].get<uint64_t>()),
    ctypeNid(json["ctypeNid"].get<int32_t>()),
    econtNid(json["econtNid"].get<int32_t>()),
    mdalgs(json["mdalgs"]),
    it(json["it"].get<uint64_t>()),
    libctx(json["libctx"]),
    propq(json["propq"])
{ }

bool SMIME_write_ASN1_ex::operator==(const SMIME_write_ASN1_ex& rhs) const {
    return
        (bioOut == rhs.bioOut) &&
        (asn1Value == rhs.asn1Value) &&
        (bioData == rhs.bioData) &&
        (flags == rhs.flags) &&
        (ctypeNid == rhs.ctypeNid) &&
        (econtNid == rhs.econtNid) &&
        (mdalgs == rhs.mdalgs) &&
        (it == rhs.it) &&
        (libctx == rhs.libctx) &&
        (propq == rhs.propq);
}

void SMIME_write_ASN1_ex::Serialize(Datasource& ds) const {
    bioOut.Serialize(ds);
    asn1Value.Serialize(ds);
    bioData.Serialize(ds);
    ds.Put<>(flags);
    ds.Put<>(ctypeNid);
    ds.Put<>(econtNid);
    mdalgs.Serialize(ds);
    ds.Put<>(it);
    libctx.Serialize(ds);
    propq.Serialize(ds);
}

nlohmann::json SMIME_write_ASN1_ex::ToJSON(void) const {
    nlohmann::json j;
    j["bioOut"] = bioOut.ToJSON();
    j["asn1Value"] = asn1Value.ToJSON();
    j["bioData"] = bioData.ToJSON();
    j["flags"] = flags;
    j["ctypeNid"] = ctypeNid;
    j["econtNid"] = econtNid;
    j["mdalgs"] = mdalgs.ToJSON();
    j["it"] = it;
    j["libctx"] = libctx.ToJSON();
    j["propq"] = propq.ToJSON();
    return j;
}

SMIME_write_ASN1_ex SMIME_write_ASN1_ex::Mutate(Datasource& ds, size_t mutatorId) const {
    switch ( mutatorId ) {
        case 0: {
            SMIME_write_ASN1_ex_Pair p = {0};
            std::optional<SMIME_write_ASN1_ex_Pair> v = Pool_SMIME_write_ASN1_ex.Get(ds);
            if ( v != std::nullopt ) {
                p = *v;
            }
            SMIME_write_ASN1_ex result(*this);
            result.flags = p.CMS_flag;
            result.flags |= p.SMIME_flag;
            return result;
        }
        default: {
            /* We could not find a mutator, return the original */
            return *this;
        }
    }
}

