class SMIME_WriteASN1Ex : public Operation {
    public:
        const Buffer out;
        const component::ASN1_Value val;
        const Buffer data;
        const int CMS_flag;
        const int SMIME_flag;
        const component::CipherType cipherType;
        const std::optional<component::Algorithms> mdalgs;
        const component::ASN1_Item it;

        SMIME_WriteASN1Ex(Datasource& ds, component::Modifier modifier) :
            Operation(std::move(modifier)),
            out(ds),
            val(ds),
            data(ds),
            CMS_flag(ds.Get<int>()),
            SMIME_flag(ds.Get<int>()),
            cipherType(ds),
            mdalgs(ds.Get<bool>() ? std::nullopt : std::make_optional<component::Algorithms>(ds)),
            it(ds)
        { }
        SMIME_WriteASN1Ex(nlohmann::json json) : 
            Operation(json["modifier"]),
            out(json["out"]),
            val(json["val"]),
            data(json["data"]),
            CMS_flag(json["CMS_flag"].get<int>()),
            SMIME_flag(json["SMIME_flag"].get<int>()),
            cipherType(json["cipherType"]),
            mdalgs(
                json["mdalgs_enabled"].get<bool>() ?
                std::optional<component::Algorithms>(json["mdalgs"]) :
                std::optional<component::Algorithms>(std::nullopt)
            ),
            it(json["it"])
        { }

        static size_t MaxOperations(void) { return 5; }
        std::string Name(void) const override;
        std::string ToString(void) const override;
        nlohmann::json ToJSON(void) const override;
        inline bool operator==(const SMIME_WriteASN1Ex& rhs) const {
            return
                (out == rhs.out) &&
                (val == rhs.val) &&
                (data == rhs.data) &&
                (CMS_flag == rhs.CMS_flag) &&
                (SMIME_flag == rhs.SMIME_flag) &&
                (cipherType == rhs.cipherType) &&
                (mdalgs == rhs.mdalgs) &&
                (it == rhs.it) &&
                (modifier == rhs.modifier);
        }
        void Serialize(Datasource& ds) const {
            out.Serialize(ds);
            val.Serialize(ds);
            data.Serialize(ds);
            ds.Put<>(CMS_flag);
            ds.Put<>(SMIME_flag);
            cipherType.Serialize(ds);
            if ( mdalgs == std::nullopt ) {
                ds.Put<bool>(true);
            } else {
                ds.Put<bool>(false);
                mdalgs->Serialize(ds);
            }
            it.Serialize(ds);
        }
};
