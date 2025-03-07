std::optional<component::Digest> OpenSSL::OpSMIME_write_ASN1_ex(operation::SMIME_write_ASN1_ex& op) {
    std::optional<component::Digest> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    CF_EVP_MD_CTX ctx(ds);

    /* Initialize */
    {
        CF_CHECK_NE(toEVPCMSFlag(op.CMS_flag), nullptr);
        CF_CHECK_NE(toEVPSMIMEFlag(op.SMIME_flag), nullptr);
        CF_CHECK_NE(toEVPCipher(op.cipherType), nullptr);
    }

    /* Process */
    {

        /* En/Decrypt the cleartext */
        {
        }
    }

end:

    return ret;
}
