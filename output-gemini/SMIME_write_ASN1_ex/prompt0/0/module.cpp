std::optional<bool> OpenSSL::OpSMIME_write_ASN1_ex(operation::SMIME_write_ASN1& op) {
    std::optional<bool> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    SMIME_write_ASN1_ex ctx(ds);
    BIO *bio_mem = nullptr;
    
    try {
        /* Create BIO for input data */
        bio_mem = BIO_new(BIO_s_mem());
        if (bio_mem == NULL) {
            goto end;
        }

        /* Write data to BIO */
        if (BIO_write(bio_mem, op.cleartext.GetPtr(), op.cleartext.GetSize()) <= 0) {
            goto end;
        }

        /* Set up SMIME_write_ASN1_ex context */
        ctx.out = BIO_new(BIO_s_null());
        if (ctx.out == NULL) {
            goto end;
        }
        
        ctx.data = bio_mem;
        ctx.flags = op.CMS_flags.Get() | op.SMIME_flags.Get();
        ctx.ctype_nid = OBJ_obj2nid(op.cipherType.GetPtr());
        /* TODO: set the rest of the parameters */

        if (SMIME_write_ASN1_ex(ctx.out, ctx.val, ctx.data, ctx.flags, ctx.ctype_nid,
                           ctx.econt_nid, ctx.mdalgs, ctx.it, ctx.libctx, ctx.propq) != 1) {
            goto end;
        }

        ret = true;

    } catch (fuzzing::datasource::Datasource::OutOfData) {
    }

end:
    BIO_free_all(bio_mem);
    BIO_free_all(ctx.out);

    return ret;
}
