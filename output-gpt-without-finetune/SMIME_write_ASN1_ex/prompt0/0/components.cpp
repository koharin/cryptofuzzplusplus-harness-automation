/* SMIME_Encryption_Params */

SMIME_Encryption_Params::SMIME_Encryption_Params(Datasource& ds) :
    CMS_flag(ds.Get<int>()),
    SMIME_flag(ds.Get<int>()),
    cipherType(ds.Get<int>())
{ }

SMIME_Encryption_Params::SMIME_Encryption_Params(nlohmann::json json) :
    CMS_flag(json["CMS_flag"].get<int>()),
    SMIME_flag(json["SMIME_flag"].get<int>()),
    cipherType(json["cipherType"].get<int>())
{ }

nlohmann::json SMIME_Encryption_Params::ToJSON(void) const {
    nlohmann::json j;
    j["CMS_flag"] = CMS_flag;
    j["SMIME_flag"] = SMIME_flag;
    j["cipherType"] = cipherType;
    return j;
}

bool SMIME_Encryption_Params::operator==(const SMIME_Encryption_Params& rhs) const {
    return
        (CMS_flag == rhs.CMS_flag) &&
        (SMIME_flag == rhs.SMIME_flag) &&
        (cipherType == rhs.cipherType);
}

void SMIME_Encryption_Params::Serialize(Datasource& ds) const {
    ds.Put<>(CMS_flag);
    ds.Put<>(SMIME_flag);
    ds.Put<>(cipherType);
}
