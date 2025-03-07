std::string ToString(const Buffer& buffer) {
    return HexDump(buffer.Get());
}

std::string ToString(const bool val) {
    return val ? "true" : "false";
}

std::string ToString(const component::Ciphertext& ciphertext) {
    std::string ret;

    ret += util::HexDump(ciphertext.ciphertext.GetPtr(), ciphertext.ciphertext.GetSize(), "ciphertext");

    ret += "\n";

    if ( ciphertext.tag != std::nullopt ) {
        ret += util::HexDump(ciphertext.tag->GetPtr(), ciphertext.tag->GetSize(), "tag");
    } else {
        ret += "(tag is nullopt)";
    }

    return ret;
}

std::string ToString(const component::ECC_PublicKey& val) {
    std::string ret;

    ret += "X: ";
    ret += val.first.ToString();
    ret += "\n";

    ret += "Y: ";
    ret += val.second.ToString();
    ret += "\n";

    return ret;
}

std::string ToString(const component::ECC_KeyPair& val) {
    std::string ret;

    ret += "Priv: ";
    ret += val.priv.ToString();
    ret += "\n";

    ret += "X: ";
    ret += val.pub.first.ToString();
    ret += "\n";

    ret += "Y: ";
    ret += val.pub.second.ToString();
    ret += "\n";

    return ret;
}

std::string ToString(const component::ECDSA_Signature& val) {
    std::string ret;

    ret += "X: ";
    ret += val.pub.first.ToString();
    ret += "\n";

    ret += "Y: ";
    ret += val.pub.second.ToString();
    ret += "\n";

    ret += "R: ";
    ret += val.signature.first.ToString();
    ret += "\n";

    ret += "S: ";
    ret += val.signature.second.ToString();
    ret += "\n";

    return ret;
}

std::string ToString(const component::BLS_Signature& val) {
    std::string ret;

    ret += "Pub X: ";
    ret += val.pub.first.ToString();
    ret += "\n";

    ret += "Pub Y: ";
    ret += val.pub.second.ToString();
    ret += "\n";

    ret += "Sig v: ";
    ret += val.signature.first.first.ToString();
    ret += "\n";

    ret += "Sig w: ";
    ret += val.signature.first.second.ToString();
    ret += "\n";

    ret += "Sig x: ";
    ret += val.signature.second.first.ToString();
    ret += "\n";

    ret += "Sig y: ";
    ret += val.signature.second.second.ToString();
    ret += "\n";

    return ret;
}

std::string ToString(const component::BLS_BatchSignature& val) {
    std::string ret;

    for (const auto& cur : val.msgpub) {
        ret += "G1 X: ";
        ret += cur.first.first.ToString();
        ret += "\n";
        ret += "G1 Y: ";
        ret += cur.first.second.ToString();
        ret += "\n";

        ret += "\n";

        ret += "G2 V: ";
        ret += cur.second.first.first.ToString();
        ret += "\n";
        ret += "G2 W: ";
        ret += cur.second.first.second.ToString();
        ret += "\n";
        ret += "G2 X: ";
        ret += cur.second.second.first.ToString();
        ret += "\n";
        ret += "G2 Y: ";
        ret += cur.second.second.second.ToString();
        ret += "\n";

        ret += "----------";
        ret += "\n";
    }
    return ret;
}

std::string ToString(const component::BLS_KeyPair& val) {
    std::string ret;

    ret += "Priv : ";
    ret += val.priv.ToString();
    ret += "\n";

    ret += "Pub X: ";
    ret += val.pub.first.ToString();
    ret += "\n";

    ret += "Pub Y: ";
    ret += val.pub.second.ToString();
    ret += "\n";

    return ret;
}

std::string ToString(const component::Bignum& val) {
    return val.ToString();
}

std::string ToString(const component::G2& val) {
    std::string ret;

    ret += "X1: ";
    ret += val.first.first.ToString();
    ret += "\n";

    ret += "Y1: ";
    ret += val.first.second.ToString();
    ret += "\n";

    ret += "X2: ";
    ret += val.second.first.ToString();
    ret += "\n";

    ret += "Y2: ";
    ret += val.second.second.ToString();
    ret += "\n";

    return ret;
}

std::string ToString(const component::Fp12& val) {
    std::string ret;

    ret += "bn1: " + val.bn1.ToString() + "\n";
    ret += "bn2: " + val.bn2.ToString() + "\n";
    ret += "bn3: " + val.bn3.ToString() + "\n";
    ret += "bn4: " + val.bn4.ToString() + "\n";
    ret += "bn5: " + val.bn5.ToString() + "\n";
    ret += "bn6: " + val.bn6.ToString() + "\n";
    ret += "bn7: " + val.bn7.ToString() + "\n";
    ret += "bn8: " + val.bn8.ToString() + "\n";
    ret += "bn9: " + val.bn9.ToString() + "\n";
    ret += "bn10: " + val.bn10.ToString() + "\n";
    ret += "bn11: " + val.bn11.ToString() + "\n";
    ret += "bn12: " + val.bn12.ToString() + "\n";

    return ret;
}

std::string ToString(const component::RSA_KeyPair& val) {
    std::string ret;

    ret += "n: " + val.n + "\n";
    ret += "e: " + val.e + "\n";
    ret += "d: " + val.d + "\n";

    return ret;
}

nlohmann::json ToJSON(const Buffer& buffer) {
    return buffer.ToJSON();
}

nlohmann::json ToJSON(const bool val) {
    return val;
}

nlohmann::json ToJSON(const component::Ciphertext& ciphertext) {
    nlohmann::json ret;

    ret["ciphertext"] = ciphertext.ciphertext.ToJSON();

    if ( ciphertext.tag != std::nullopt ) {
        ret["tag"] = ciphertext.tag->ToJSON();
    }

    return ret;
}

nlohmann::json ToJSON(const component::ECC_PublicKey& val) {
    return val.ToJSON();
}

nlohmann::json ToJSON(const component::ECC_KeyPair& val) {
    return val.ToJSON();
}

nlohmann::json ToJSON(const component::ECDSA_Signature& val) {
    return val.ToJSON();
}

nlohmann::json ToJSON(const component::Bignum& val) {
    return val.ToJSON();
}

nlohmann::json ToJSON(const component::G2& val) {
    return val.ToJSON();
}

nlohmann::json ToJSON(const component::BLS_Signature& val) {
    return val.ToJSON();
}

nlohmann::json ToJSON(const component::BLS_BatchSignature& val) {
    return val.ToJSON();
}

nlohmann::json ToJSON(const component::BLS_KeyPair& val) {
    return val.ToJSON();
}

nlohmann::json ToJSON(const component::Fp12& val) {
    return val.ToJSON();
}

nlohmann::json ToJSON(const component::RSA_KeyPair& val) {
    return val.ToJSON();
}