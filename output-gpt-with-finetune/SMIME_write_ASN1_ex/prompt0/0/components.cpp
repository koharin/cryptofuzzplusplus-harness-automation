/* SMIME_write_ASN1_ex */

SMIME_write_ASN1_ex::SMIME_write_ASN1_ex(Datasource& ds) :
    CMS_flag(ds),
    SMIME_flag(ds),
    cipherType(ds)
{ }

SMIME_write_ASN1_ex::SMIME_write_ASN1_ex(nlohmann::json json) :
    CMS_flag(json["CMS_flag"]),
    SMIME_flag(json["SMIME_flag"]),
    cipherType(json["cipherType"])
{ }

nlohmann::json SMIME_write_ASN1_ex::ToJSON(void) const {
    nlohmann::json j;
    j["CMS_flag"] = CMS_flag.ToJSON();
    j["SMIME_flag"] = SMIME_flag.ToJSON();
    j["cipherType"] = cipherType.ToJSON();
    return j;
}

bool SMIME_write_ASN1_ex::operator==(const SMIME_write_ASN1_ex& rhs) const {
    return
        (CMS_flag == rhs.CMS_flag) &&
        (SMIME_flag == rhs.SMIME_flag) &&
        (cipherType == rhs.cipherType);
}

void SMIME_write_ASN1_ex::Serialize(Datasource& ds) const {
    CMS_flag.Serialize(ds);
    SMIME_flag.Serialize(ds);
    cipherType.Serialize(ds);
}
