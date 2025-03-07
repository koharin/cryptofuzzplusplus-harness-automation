std::optional<component::SMIME_Result> OpenSSL::OpSMIME_WriteASN1Ex(operation::SMIME_WriteASN1Ex& op, Datasource& ds) {
    std::optional<component::SMIME_Result> ret = std::nullopt;

    BIO* out_bio = nullptr;
    BIO* data_bio = nullptr;
    ASN1_VALUE* asn1_val = nullptr;
    STACK_OF(X509_ALGOR)* mdalgs = nullptr;

    /* Initialize */
    {
        out_bio = BIO_new_mem_buf(op.out.GetPtr(), op.out.GetSize());
        CF_CHECK_NE(out_bio, nullptr);

        data_bio = BIO_new_mem_buf(op.data.GetPtr(), op.data.GetSize());
        CF_CHECK_NE(data_bio, nullptr);

        asn1_val = (ASN1_VALUE*)ASN1_ITEM_ptr(op.val.GetPtr());
        CF_CHECK_NE(asn1_val, nullptr);

        if (op.mdalgs != std::nullopt) {
            mdalgs = op.mdalgs->ToStackOfX509_ALGOR();
        }
    }

    /* Process */
    {
        const int flags = op.CMS_flag | op.SMIME_flag;
        const int ctype_nid = OBJ_nid2obj(op.cipherType.Get());

        CF_CHECK_EQ(
            SMIME_write_ASN1_ex(
                out_bio, 
                asn1_val, 
                data_bio, 
                flags, 
                ctype_nid, 
                NID_undef, 
                mdalgs, 
                ASN1_ITEM_rptr(op.it.Get()), 
                nullptr, 
                nullptr
            ), 1);
    }

    /* Finalize */
    {
        BUF_MEM* buffer_ptr = nullptr;
        BIO_get_mem_ptr(out_bio, &buffer_ptr);

        ret = component::SMIME_Result(
            Buffer(buffer_ptr->data, buffer_ptr->length)
        );
    }

end:
    BIO_free(out_bio);
    BIO_free(data_bio);
    sk_X509_ALGOR_pop_free(mdalgs, X509_ALGOR_free);

    return ret;
}
