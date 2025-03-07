virtual std::optional<component::SMIME_Result> OpSMIME_WriteASN1Ex(operation::SMIME_WriteASN1Ex& op) {
    std::optional<component::SMIME_Result> ret = std::nullopt;
    BIO* out_bio = nullptr;
    BIO* data_bio = nullptr;
    ASN1_VALUE* asn1_val = nullptr;
    STACK_OF(X509_ALGOR)* mdalgs = nullptr;

    /* Initialize */
    {
        out_bio = BIO_new_mem_buf(op.out.GetPtr(), op.out.GetSize());
        if (!out_bio) return std::nullopt;

        data_bio = BIO_new_mem_buf(op.data.GetPtr(), op.data.GetSize());
        if (!data_bio) {
            BIO_free(out_bio);
            return std::nullopt;
        }

        asn1_val = (ASN1_VALUE*)ASN1_ITEM_ptr(op.val.GetPtr());
        if (!asn1_val) {
            BIO_free(out_bio);
            BIO_free(data_bio);
            return std::nullopt;
        }

        if (op.mdalgs != std::nullopt) {
            mdalgs = op.mdalgs->ToStackOfX509_ALGOR();
        }
    }

    /* Process */
    {
        const int flags = op.CMS_flag | op.SMIME_flag;
        const int ctype_nid = OBJ_nid2obj(op.cipherType.Get());

        if (SMIME_write_ASN1_ex(out_bio, asn1_val, data_bio, flags, ctype_nid, NID_undef, mdalgs, ASN1_ITEM_rptr(op.it.Get()), nullptr, nullptr) != 1) {
            BIO_free(out_bio);
            BIO_free(data_bio);
            sk_X509_ALGOR_pop_free(mdalgs, X509_ALGOR_free);
            return std::nullopt;
        }
    }

    /* Finalize */
    {
        BUF_MEM* buffer_ptr = nullptr;
        BIO_get_mem_ptr(out_bio, &buffer_ptr);

        ret = component::SMIME_Result(
            Buffer(buffer_ptr->data, buffer_ptr->length)
        );
    }

    BIO_free(out_bio);
    BIO_free(data_bio);
    sk_X509_ALGOR_pop_free(mdalgs, X509_ALGOR_free);

    return ret;
}
