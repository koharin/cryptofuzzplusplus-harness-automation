class SMIME_write_ASN1_ex : public Operation {
    protected:
        const CurveType curveType;

    public:
        const DigestType digestType;
        const Cleartext cleartext;
        const bool enc;

        const std::optional<component::G2> pub;
        const std::optional<component::G2> priv;

        SMIME_write_ASN1_ex(Datasource& ds) :
            Operation(std::nullopt),
            curveType(ds),
            digestType(ds),
            cleartext(ds),
            enc(ds.Get<bool>()),
            pub(ds.Get<bool>() ? std::optional<component::G2>(ds) : std::nullopt),
            priv(ds.Get<bool>() ? std::optional<component::G2>(ds) : std::nullopt)
        { }
        SMIME_write_ASN1_ex(nlohmann::json json) :
            Operation(json["operation"]),
            curveType(json["curveType"]),
            digestType(json["digestType"]),
            cleartext(json["cleartext"]),
            enc(json["enc"]),
            pub(json["pub_enabled"] == true ? std::optional<component::G2>(json["pub"]) : std::nullopt),
            priv(json["priv_enabled"] == true ? std::optional<component::G2>(json["priv"]) : std::nullopt)
        { }

        void Serialize(Datasource& ds) const;
        nlohmann::json ToJSON(void) const;
        bool operator==(const SMIME_write_ASN1_ex& rhs) const;
};

void SMIME_write_ASN1_ex::Serialize(Datasource& ds) const {
    Operation::Serialize(ds);
    curveType.Serialize(ds);
    cleartext.Serialize(ds);
    util::PutBool(ds, enc);

    if ( pub == std::nullopt ) {
        util::PutBool(ds, false);
    } else {
        util::PutBool(ds, true);
        pub->Serialize(ds);
    }

    if ( priv == std::nullopt ) {
        util::PutBool(ds, false);
    } else {
        util::PutBool(ds, true);
        priv->Serialize(ds);
    }
}

nlohmann::json SMIME_write_ASN1_ex::ToJSON(void) const {
    nlohmann::json json;

    json["operation"] = Operation::ToJSON();
    json["curveType"] = curveType.ToJSON();
    json["digestType"] = digestType.ToJSON();
    json["cleartext"] = cleartext.ToJSON();
    json["enc"] = enc;

    if ( pub == std::nullopt ) {
        json["pub_enabled"] = false;
    } else {
        json["pub_enabled"] = true;
        json["pub"] = pub->ToJSON();
    }

    if ( priv == std::nullopt ) {
        json["priv_enabled"] = false;
    } else {
        json["priv_enabled"] = true;
        json["priv"] = priv->ToJSON();
    }

    return json;
}

bool SMIME_write_ASN1_ex::operator==(const SMIME_write_ASN1_ex& rhs) const {
    return
        (Operation::operator==(rhs)) &&
        (curveType == rhs.curveType) &&
        (digestType == rhs.digestType) &&
        (cleartext == rhs.cleartext) &&
        (enc == rhs.enc) &&
        (pub == rhs.pub) &&
        (priv == rhs.priv);
}
