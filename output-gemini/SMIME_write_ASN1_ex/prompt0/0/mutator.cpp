            case    CF_OPERATION("SMIME_write_ASN1_ex"):
                {
                    size_t numParts = 0;

                    numParts++; /* modifier */
                    numParts++; /* cleartext */
                    numParts++; /* serial */
                    numParts++; /* version */

                    const auto lengths = SplitLength(maxSize - 64, numParts);

                    parameters["modifier"] = getBuffer(lengths[0]);
                    parameters["cleartext"] = getBuffer(lengths[1]);
                    parameters["CMS_flags"] = getRandomCMS_flag();
                    parameters["SMIME_flags"] = getRandomSMIME_flag();
                    parameters["cipherType"] = getRandomCipher();
                    parameters["serial"] = getBignum();
                    parameters["version"] = getBignum();

                    cryptofuzz::operation::SMIME_write_ASN1 op(parameters);
                    op.Serialize(dsOut2);
                }
                break;
