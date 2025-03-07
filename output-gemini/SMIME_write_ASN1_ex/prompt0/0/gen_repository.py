operations.Add( Operation("SMIME_write_ASN1_ex")
    .AddParameter( Parameter("CMS_flag")
        .AddValue(ID("CMS_TEXT"))
        .AddValue(ID("CMS_DETACHED"))
        .AddValue(ID("CMS_STREAM"))
        .AddValue(ID("CMS_BINARY"))
        .AddValue(ID("CMS_PARTIAL"))
        .AddValue(ID("CMS_REUSE_DIGEST"))
        .AddValue(ID("CMS_USE_KEYID"))
        .AddValue(ID("CMS_DEBUG_DECRYPT"))
        /* ... add other CMS_* flags */
    )
    .AddParameter( Parameter("SMIME_flag")
        .AddValue(ID("SMIME_OLDMIME"))
        /* ... add other SMIME_* flags */
    )
    .AddParameter( Parameter("cipherType")
        .AddValue(ID("EVP_des_ede3_cbc")) 
        /* ... add other cipher types */
    )
    /* ... add other parameters as needed */
);
