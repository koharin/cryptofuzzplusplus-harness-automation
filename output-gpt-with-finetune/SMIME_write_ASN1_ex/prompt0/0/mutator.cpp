            case    CF_OPERATION("SMIME_write_ASN1_ex"):
                {
                    parameters["modifier"] = getBuffer(PRNG() % 1000);
                    parameters["cleartext"] = getBuffer(PRNG() % 1024);

                    const bool pub_enabled = PRNG() % 2;
                    parameters["pub_enabled"] = pub_enabled;
                    if ( pub_enabled == true ) {
                        parameters["pub"]["v"] = getBignum();
                        parameters["pub"]["w"] = getBignum();
                        parameters["pub"]["x"] = getBignum();
                        parameters["pub"]["y"] = getBignum();
                    }

                    const bool priv_enabled = PRNG() % 2;
                    parameters["priv_enabled"] = priv_enabled;
                    if ( priv_enabled == true ) {
                        parameters["priv"]["v"] = getBignum();
                        parameters["priv"]["w"] = getBignum();
                        parameters["priv"]["x"] = getBignum();
                        parameters["priv"]["y"] = getBignum();
                    }

                    parameters["CMS_flag"] = std::vector<uint64_t>{
                        PRNG(),
                        PRNG(),
                        PRNG(),
                        PRNG()
                    };

                    parameters["SMIME_flag"] = std::vector<uint64_t>{
                        PRNG(),
                        PRNG(),
                        PRNG(),
                        PRNG()
                    };

                    parameters["cipherType"] = getRandomCipher();
                    parameters["curveType"] = getRandomCurve();

                    parameters["ctype_nid"] = PRNG();
                    parameters["econt_nid"] = PRNG();

                    cryptofuzz::operation::SMIME_write_ASN1_ex op(parameters);
                    op.Serialize(dsOut2);
                }
                break;
