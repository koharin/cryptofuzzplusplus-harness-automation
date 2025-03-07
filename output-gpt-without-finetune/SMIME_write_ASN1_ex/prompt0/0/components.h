class SMI_ME_EncryptionParams {
    public:
        int CMS_flag;
        int SMIME_flag;
        int cipherType;

        SMI_ME_EncryptionParams(Datasource& ds) {
            CMS_flag = ds.Get<int>();
            SMIME_flag = ds.Get<int>();
            cipherType = ds.Get<int>();
        }

        SMI_ME_EncryptionParams(nlohmann::json json) {
            CMS_flag = json["CMS_flag"].get<int>();
            SMIME_flag = json["SMIME_flag"].get<int>();
            cipherType = json["cipherType"].get<int>();
        }

        nlohmann::json ToJSON(void) const {
            nlohmann::json json;
            json["CMS_flag"] = CMS_flag;
            json["SMIME_flag"] = SMIME_flag;
            json["cipherType"] = cipherType;
            return json;
        }

        bool operator==(const SMI_ME_EncryptionParams& rhs) const {
            return CMS_flag == rhs.CMS_flag &&
                   SMIME_flag == rhs.SMIME_flag &&
                   cipherType == rhs.cipherType;
        }

        void Serialize(Datasource& ds) const {
            ds.Put<int>(CMS_flag);
            ds.Put<int>(SMIME_flag);
            ds.Put<int>(cipherType);
        }
};
