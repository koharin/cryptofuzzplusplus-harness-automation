            case    CF_OPERATION("Digest"):
                {
                    parameters["modifier"] = "";
                    parameters["cleartext"] = getBuffer(PRNG64() % maxSize);
                    parameters["digestType"] = getRandomDigest();

                    cryptofuzz::operation::Digest op(parameters);
                    op.Serialize(dsOut2);
                }
                break;
            case    CF_OPERATION("HMAC"):
                {
                    size_t numParts = 0;

                    numParts++; /* modifier */
                    numParts++; /* cleartext */
                    numParts++; /* iv */
                    numParts++; /* key */

                    const auto lengths = SplitLength(maxSize - 64, numParts);

                    parameters["modifier"] = getBuffer(lengths[0]);
                    parameters["cleartext"] = getBuffer(lengths[1]);
                    parameters["cipher"]["iv"] = getBuffer(lengths[2], true);
                    parameters["cipher"]["key"] = getBuffer(lengths[3], true);
                    parameters["cipher"]["cipherType"] = getRandomCipher();
                    parameters["digestType"] = getRandomDigest();

                    cryptofuzz::operation::HMAC op(parameters);
                    op.Serialize(dsOut2);
                }
                break;
            case    CF_OPERATION("UMAC"):
                {
                    parameters["modifier"] = "";
                    parameters["cleartext"] = getBuffer(PRNG64() % maxSize);
                    parameters["key"] = getBuffer(16);
                    parameters["iv"] = getBuffer(PRNG() % 17);
                    parameters["type"] = PRNG() % 4;
                    parameters["outSize"] = PRNG() % 1024;

                    cryptofuzz::operation::UMAC op(parameters);
                    op.Serialize(dsOut2);
                }
                break;
            case    CF_OPERATION("CMAC"):
                {
                    size_t numParts = 0;

                    numParts++; /* modifier */
                    numParts++; /* cleartext */
                    numParts++; /* iv */
                    numParts++; /* key */

                    const auto lengths = SplitLength(maxSize - 64, numParts);

                    parameters["modifier"] = getBuffer(lengths[0]);
                    parameters["cleartext"] = getBuffer(lengths[1]);
                    parameters["cipher"]["iv"] = getBuffer(lengths[2], true);
                    parameters["cipher"]["key"] = getBuffer(lengths[3], true);
                    parameters["cipher"]["cipherType"] = getRandomCipher();

                    cryptofuzz::operation::CMAC op(parameters);
                    op.Serialize(dsOut2);
                }
                break;
            case    CF_OPERATION("SymmetricEncrypt"):
                {
                    const bool aad_enabled = PRNG() % 2;
                    const bool tagSize_enabled = PRNG() % 2;
                    size_t numParts = 0;

                    numParts++; /* modifier */
                    numParts++; /* cleartext */
                    numParts++; /* iv */
                    numParts++; /* key */

                    if ( aad_enabled ) {
                        numParts++; /* aad */
                    }

                    auto lengths = SplitLength(maxSize - 64, numParts);

                    parameters["modifier"] = getBuffer(lengths[0]);
                    if ( getBool() ) {
                        if ( 16 < lengths[1] ) {
                            lengths[1] = 16;
                        }
                    }
                    parameters["cleartext"] = getBuffer(lengths[1]);

                    parameters["cipher"]["iv"] = getBuffer(lengths[2], true);
                    parameters["cipher"]["key"] = getBuffer(lengths[3], true);

                    if ( aad_enabled ) {
                        parameters["aad_enabled"] = true;
                        if ( getBool() ) {
                            lengths[4] = 0;
                        }
                        parameters["aad"] = getBuffer(lengths[4]);
                    } else {
                        parameters["aad_enabled"] = false;
                    }

                    if ( tagSize_enabled ) {
                        parameters["tagSize_enabled"] = true;
                        if ( getBool() ) {
                            parameters["tagSize"] = getDefaultSize();
                        } else {
                            parameters["tagSize"] = PRNG() % 102400;
                        }
                    } else {
                        parameters["tagSize_enabled"] = false;
                    }

                    parameters["cipher"]["cipherType"] = getRandomCipher();
                    parameters["ciphertextSize"] = PRNG() % (lengths[1] + 9);

                    cryptofuzz::operation::SymmetricEncrypt op(parameters);
                    op.Serialize(dsOut2);
                }
                break;
            case    CF_OPERATION("SymmetricDecrypt"):
                {
                    const bool aad_enabled = PRNG() % 2;
                    const bool tag_enabled = PRNG() % 2;
                    size_t numParts = 0;

                    numParts++; /* modifier */
                    numParts++; /* cleartext */
                    numParts++; /* iv */
                    numParts++; /* key */

                    if ( aad_enabled ) {
                        numParts++; /* aad */
                    }
                    if ( tag_enabled ) {
                        numParts++; /* tag */
                    }

                    auto lengths = SplitLength(maxSize - 64, numParts);

                    parameters["modifier"] = getBuffer(lengths[0]);
                    if ( getBool() ) {
                        if ( 16 < lengths[1] ) {
                            lengths[1] = 16;
                        }
                    }
                    parameters["ciphertext"] = getBuffer(lengths[1]);

                    parameters["cipher"]["iv"] = getBuffer(lengths[2], true);
                    parameters["cipher"]["key"] = getBuffer(lengths[3], true);

                    if ( aad_enabled ) {
                        parameters["aad_enabled"] = true;
                        if ( getBool() ) {
                            lengths[4] = 0;
                        }
                        parameters["aad"] = getBuffer(lengths[4]);
                    } else {
                        parameters["aad_enabled"] = false;
                    }

                    if ( tag_enabled ) {
                        parameters["tag_enabled"] = true;
                        parameters["tag"] = getBuffer(lengths[aad_enabled ? 5 : 4], true);
                    } else {
                        parameters["tag_enabled"] = false;
                    }

                    parameters["cipher"]["cipherType"] = getRandomCipher();
                    parameters["cleartextSize"] = PRNG() % (lengths[1] + 9);

                    cryptofuzz::operation::SymmetricDecrypt op(parameters);
                    op.Serialize(dsOut2);
                }
                break;
            case    CF_OPERATION("BignumCalc"):
            case    CF_OPERATION("BignumCalc_Mod_BLS12_381_R"):
            case    CF_OPERATION("BignumCalc_Mod_BLS12_381_P"):
            case    CF_OPERATION("BignumCalc_Mod_BN128_R"):
            case    CF_OPERATION("BignumCalc_Mod_BN128_P"):
            case    CF_OPERATION("BignumCalc_Mod_ED25519"):
            case    CF_OPERATION("BignumCalc_Mod_Edwards_R"):
            case    CF_OPERATION("BignumCalc_Mod_Edwards_P"):
            case    CF_OPERATION("BignumCalc_Mod_MNT4_R"):
            case    CF_OPERATION("BignumCalc_Mod_MNT4_P"):
            case    CF_OPERATION("BignumCalc_Mod_MNT6_R"):
            case    CF_OPERATION("BignumCalc_Mod_MNT6_P"):
            case    CF_OPERATION("BignumCalc_Mod_2Exp64"):
            case    CF_OPERATION("BignumCalc_Mod_2Exp128"):
            case    CF_OPERATION("BignumCalc_Mod_2Exp256"):
            case    CF_OPERATION("BignumCalc_Mod_2Exp512"):
            case    CF_OPERATION("BignumCalc_Mod_SECP256K1"):
            case    CF_OPERATION("BignumCalc_Mod_SECP256K1_P"):
                {
                    parameters["modifier"] = "";

                    const auto calcop = getRandomCalcOp();
                    parameters["calcOp"] = calcop;

                    auto bn1 = getBignum();
                    const auto bn2 = getBignum();
                    const auto bn3 = getBignum();

                    if ( calcop == CF_CALCOP("InvMod(A,B)") || calcop == CF_CALCOP("ExpMod(A,B,C)") ) {
                        std::optional<std::string> mod = get_op_mod(operation);

                        if ( mod == std::nullopt ) {
                            if ( calcop == CF_CALCOP("InvMod(A,B)") ) {
                                mod = bn2;
                            } else if ( CF_CALCOP("ExpMod(A,B,C)") ) {
                                mod = bn3;
                            } else {
                                abort();
                            }
                        }

                        const auto mont = from_mont(mutateBinary(getBignum()), *mod);
                        Pool_Bignum.Set(mont);

                        if ( getBool() ) {
                            bn1 = mont;
                        }
                    }

                    parameters["bn1"] = bn1;
                    parameters["bn2"] = bn2;
                    parameters["bn3"] = bn3;
                    parameters["bn4"] = "";

                    if ( calcop == CF_CALCOP("ExpMod(A,B,C)") && operation == CF_OPERATION("BignumCalc") ) {
                        if ( PRNG() % 100 == 0 ) {
                            const auto p = cryptofuzz::mutator::ExpModGenerator::generate_exp_mod(getBignum(true));

                            if ( p != std::nullopt ) {
                                parameters = *p;
                            }
                        }
                    }
#if defined(CRYPTOFUZZ_HAVE_Z3)
                    else if ( (PRNG() % 1000) == 0 ) {
                        const auto p = cryptofuzz::Z3::Generate(calcop);
                        if ( p != std::nullopt ) {
                            parameters = *p;
                        }
                    }
#endif
                    cryptofuzz::operation::BignumCalc op(parameters);
                    op.Serialize(dsOut2);
                }
                break;
            case    CF_OPERATION("BignumCalc_Fp2"):
                {
                    parameters["modifier"] = getBuffer(PRNG() % 1000);
                    parameters["calcOp"] = getRandomCalcOp();
                    parameters["bn1"][0] = getBignum();
                    parameters["bn1"][1] = getBignum();
                    parameters["bn2"][0] = getBignum();
                    parameters["bn2"][1] = getBignum();
                    parameters["bn3"][0] = "";
                    parameters["bn3"][1] = "";
                    parameters["bn4"][0] = "";
                    parameters["bn4"][1] = "";

                    cryptofuzz::operation::BignumCalc_Fp2 op(parameters);
                    op.Serialize(dsOut2);
                }
                break;

            case    CF_OPERATION("BignumCalc_Fp12"):
                {
                    parameters["modifier"] = getBuffer(PRNG() % 1000);
                    parameters["calcOp"] = getRandomCalcOp();

                    if ( Pool_Fp12.Have() && getBool() == true ) {
                        const auto Fp12 = Pool_Fp12.Get();
#if 0
                        parameters["bn1"][0] = GET_OR_BIGNUM(Fp12.bn1);
                        parameters["bn1"][1] = GET_OR_BIGNUM(Fp12.bn2);
                        parameters["bn1"][2] = GET_OR_BIGNUM(Fp12.bn3);
                        parameters["bn1"][3] = GET_OR_BIGNUM(Fp12.bn4);
                        parameters["bn1"][4] = GET_OR_BIGNUM(Fp12.bn5);
                        parameters["bn1"][5] = GET_OR_BIGNUM(Fp12.bn6);
                        parameters["bn1"][6] = GET_OR_BIGNUM(Fp12.bn7);
                        parameters["bn1"][7] = GET_OR_BIGNUM(Fp12.bn8);
                        parameters["bn1"][8] = GET_OR_BIGNUM(Fp12.bn9);
                        parameters["bn1"][9] = GET_OR_BIGNUM(Fp12.bn10);
                        parameters["bn1"][10] = GET_OR_BIGNUM(Fp12.bn11);
                        parameters["bn1"][11] = GET_OR_BIGNUM(Fp12.bn12);
#endif
                        parameters["bn1"][0] = Fp12.bn1;
                        parameters["bn1"][1] = Fp12.bn2;
                        parameters["bn1"][2] = Fp12.bn3;
                        parameters["bn1"][3] = Fp12.bn4;
                        parameters["bn1"][4] = Fp12.bn5;
                        parameters["bn1"][5] = Fp12.bn6;
                        parameters["bn1"][6] = Fp12.bn7;
                        parameters["bn1"][7] = Fp12.bn8;
                        parameters["bn1"][8] = Fp12.bn9;
                        parameters["bn1"][9] = Fp12.bn10;
                        parameters["bn1"][10] = Fp12.bn11;
                        parameters["bn1"][11] = Fp12.bn12;
                    } else {
                        parameters["bn1"][0] = getBignum();
                        parameters["bn1"][1] = getBignum();
                        parameters["bn1"][2] = getBignum();
                        parameters["bn1"][3] = getBignum();
                        parameters["bn1"][4] = getBignum();
                        parameters["bn1"][5] = getBignum();
                        parameters["bn1"][6] = getBignum();
                        parameters["bn1"][7] = getBignum();
                        parameters["bn1"][8] = getBignum();
                        parameters["bn1"][9] = getBignum();
                        parameters["bn1"][10] = getBignum();
                        parameters["bn1"][11] = getBignum();

                        parameters["bn2"][0] = getBignum();
                        parameters["bn2"][1] = getBignum();
                        parameters["bn2"][2] = getBignum();
                        parameters["bn2"][3] = getBignum();
                        parameters["bn2"][4] = getBignum();
                        parameters["bn2"][5] = getBignum();
                        parameters["bn2"][6] = getBignum();
                        parameters["bn2"][7] = getBignum();
                        parameters["bn2"][8] = getBignum();
                        parameters["bn2"][9] = getBignum();
                        parameters["bn2"][10] = getBignum();
                        parameters["bn2"][11] = getBignum();
                    }

                    if ( Pool_Fp12.Have() && getBool() == true ) {
                        const auto Fp12 = Pool_Fp12.Get();
#if 0
                        parameters["bn2"][0] = GET_OR_BIGNUM(Fp12.bn1);
                        parameters["bn2"][1] = GET_OR_BIGNUM(Fp12.bn2);
                        parameters["bn2"][2] = GET_OR_BIGNUM(Fp12.bn3);
                        parameters["bn2"][3] = GET_OR_BIGNUM(Fp12.bn4);
                        parameters["bn2"][4] = GET_OR_BIGNUM(Fp12.bn5);
                        parameters["bn2"][5] = GET_OR_BIGNUM(Fp12.bn6);
                        parameters["bn2"][6] = GET_OR_BIGNUM(Fp12.bn7);
                        parameters["bn2"][7] = GET_OR_BIGNUM(Fp12.bn8);
                        parameters["bn2"][8] = GET_OR_BIGNUM(Fp12.bn9);
                        parameters["bn2"][9] = GET_OR_BIGNUM(Fp12.bn10);
                        parameters["bn2"][10] = GET_OR_BIGNUM(Fp12.bn11);
                        parameters["bn2"][11] = GET_OR_BIGNUM(Fp12.bn12);
#endif
                        parameters["bn2"][0] = Fp12.bn1;
                        parameters["bn2"][1] = Fp12.bn2;
                        parameters["bn2"][2] = Fp12.bn3;
                        parameters["bn2"][3] = Fp12.bn4;
                        parameters["bn2"][4] = Fp12.bn5;
                        parameters["bn2"][5] = Fp12.bn6;
                        parameters["bn2"][6] = Fp12.bn7;
                        parameters["bn2"][7] = Fp12.bn8;
                        parameters["bn2"][8] = Fp12.bn9;
                        parameters["bn2"][9] = Fp12.bn10;
                        parameters["bn2"][10] = Fp12.bn11;
                        parameters["bn2"][11] = Fp12.bn12;
                    } else {
                        parameters["bn2"][0] = getBignum();
                        parameters["bn2"][1] = getBignum();
                        parameters["bn2"][2] = getBignum();
                        parameters["bn2"][3] = getBignum();
                        parameters["bn2"][4] = getBignum();
                        parameters["bn2"][5] = getBignum();
                        parameters["bn2"][6] = getBignum();
                        parameters["bn2"][7] = getBignum();
                        parameters["bn2"][8] = getBignum();
                        parameters["bn2"][9] = getBignum();
                        parameters["bn2"][10] = getBignum();
                        parameters["bn2"][11] = getBignum();
                    }

                    parameters["bn3"][0] = "";
                    parameters["bn3"][1] = "";
                    parameters["bn3"][2] = "";
                    parameters["bn3"][3] = "";
                    parameters["bn3"][4] = "";
                    parameters["bn3"][5] = "";
                    parameters["bn3"][6] = "";
                    parameters["bn3"][7] = "";
                    parameters["bn3"][8] = "";
                    parameters["bn3"][9] = "";
                    parameters["bn3"][10] = "";
                    parameters["bn3"][11] = "";

                    parameters["bn4"][0] = "";
                    parameters["bn4"][1] = "";
                    parameters["bn4"][2] = "";
                    parameters["bn4"][3] = "";
                    parameters["bn4"][4] = "";
                    parameters["bn4"][5] = "";
                    parameters["bn4"][6] = "";
                    parameters["bn4"][7] = "";
                    parameters["bn4"][8] = "";
                    parameters["bn4"][9] = "";
                    parameters["bn4"][10] = "";
                    parameters["bn4"][11] = "";
                    cryptofuzz::operation::BignumCalc_Fp12 op(parameters);
                    op.Serialize(dsOut2);
                }
                break;
            case    CF_OPERATION("ECC_PrivateToPublic"):
                {
                    parameters["modifier"] = getBuffer(PRNG() % 1000);

                    if ( Pool_CurvePrivkey.Have() && getBool() == true ) {
                        const auto P1 = Pool_CurvePrivkey.Get();

                        parameters["curveType"] = hint_ecc_mont(P1.curveID);
                        parameters["priv"] = P1.priv;
                    } else {
                        const auto curveID = getRandomCurve();
                        parameters["curveType"] = hint_ecc_mont(curveID);

                        if ( getBool() ) {
                            const auto order = cryptofuzz::repository::ECC_CurveToOrder(curveID);
                            if ( order != std::nullopt ) {
                                const auto o = boost::multiprecision::cpp_int(*order);
                                parameters["priv"] = boost::lexical_cast<std::string>(o-1);
                            } else {
                                parameters["priv"] = getBignum();
                            }
                        } else {
                            parameters["priv"] = getBignum();
                        }

                    }

                    cryptofuzz::operation::ECC_PrivateToPublic op(parameters);
                    op.Serialize(dsOut2);
                }
                break;
            case    CF_OPERATION("ECC_ValidatePubkey"):
                {
                    parameters["modifier"] = getBuffer(PRNG() % 1000);

                    if ( getBool() && Pool_CurveKeypair.Have() ) {
                        const auto P = Pool_CurveKeypair.Get();

                        parameters["curveType"] = hint_ecc_mont(P.curveID);

                        parameters["pub_x"] = getBool() ? getBignum() : P.pub_x;
                        parameters["pub_y"] = getBool() ? getBignum() : P.pub_y;
                    } else if ( getBool() && Pool_CurveECC_Point.Have() == true ) {
                        const auto P = Pool_CurveECC_Point.Get();
                        parameters["curveType"] = hint_ecc_mont(P.curveID);

                        parameters["pub_x"] = getBool() ? getBignum() : P.x;
                        parameters["pub_y"] = getBool() ? getBignum() : P.y;
                    } else {
                        parameters["curveType"] = hint_ecc_mont(getRandomCurve());
                        parameters["pub_x"] = getBignum();
                        parameters["pub_y"] = getBignum();
                    }

                    cryptofuzz::operation::ECC_ValidatePubkey op(parameters);
                    op.Serialize(dsOut2);

                    generateECCPoint();
                }
                break;
            case    CF_OPERATION("ECDH_Derive"):
                {
                    parameters["modifier"] = getBuffer(PRNG() % 1000);

                    if ( Pool_CurvePrivkey.Have() && getBool() == true ) {
                        const auto P1 = Pool_CurveKeypair.Get();
                        const auto P2 = Pool_CurveKeypair.Get();

                        CF_CHECK_EQ(P1.curveID, P2.curveID);

                        parameters["curveType"] = hint_ecc_mont(P1.curveID);

                        parameters["priv"] = P1.privkey;

                        parameters["pub_x"] = P1.pub_x;
                        parameters["pub_y"] = P1.pub_y;
                    } else {
                        parameters["curveType"] = hint_ecc_mont(getRandomCurve());

                        parameters["priv"] = getBignum();

                        parameters["pub_x"] = getBignum();
                        parameters["pub_y"] = getBignum();
                    }

                    cryptofuzz::operation::ECDH_Derive op(parameters);
                    op.Serialize(dsOut2);
                }
                break;
            case    CF_OPERATION("ECDSA_Sign"):
                {
                    parameters["modifier"] = getBuffer(PRNG() % 1000);

                    const auto P1 = Pool_CurvePrivkey.Get();

                    parameters["curveType"] = hint_ecc_mont(P1.curveID);
                    parameters["priv"] = P1.priv;
                    parameters["nonce"] = getBignum();

                    if ( getBool() ) {
                        parameters["cleartext"] = cryptofuzz::util::DecToHex(getBignum(true), (PRNG() % 64) * 2);
                    } else {
                        parameters["cleartext"] = getBuffer(PRNG() % 32);
                    }
                    parameters["nonceSource"] = PRNG() % 3;
                    parameters["digestType"] = getRandomDigest();

                    cryptofuzz::operation::ECDSA_Sign op(parameters);
                    op.Serialize(dsOut2);
                }
                break;
            case    CF_OPERATION("ECGDSA_Sign"):
                {
                    parameters["modifier"] = getBuffer(PRNG() % 1000);

                    const auto P1 = Pool_CurvePrivkey.Get();

                    parameters["curveType"] = hint_ecc_mont(P1.curveID);
                    parameters["priv"] = P1.priv;
                    parameters["nonce"] = getBignum();

                    if ( getBool() ) {
                        parameters["cleartext"] = cryptofuzz::util::DecToHex(getBignum(true), (PRNG() % 64) * 2);
                    } else {
                        parameters["cleartext"] = getBuffer(PRNG() % 32);
                    }
                    parameters["nonceSource"] = PRNG() % 3;
                    parameters["digestType"] = getRandomDigest();

                    cryptofuzz::operation::ECGDSA_Sign op(parameters);
                    op.Serialize(dsOut2);
                }
                break;
            case    CF_OPERATION("ECRDSA_Sign"):
                {
                    parameters["modifier"] = getBuffer(PRNG() % 1000);

                    const auto P1 = Pool_CurvePrivkey.Get();

                    parameters["curveType"] = hint_ecc_mont(P1.curveID);
                    parameters["priv"] = P1.priv;
                    parameters["nonce"] = getBignum();

                    if ( getBool() ) {
                        parameters["cleartext"] = cryptofuzz::util::DecToHex(getBignum(true), (PRNG() % 64) * 2);
                    } else {
                        parameters["cleartext"] = getBuffer(PRNG() % 32);
                    }
                    parameters["nonceSource"] = PRNG() % 3;
                    parameters["digestType"] = getRandomDigest();

                    cryptofuzz::operation::ECRDSA_Sign op(parameters);
                    op.Serialize(dsOut2);
                }
                break;
            case    CF_OPERATION("Schnorr_Sign"):
                {
                    parameters["modifier"] = getBuffer(PRNG() % 1000);

                    const auto P1 = Pool_CurvePrivkey.Get();

                    parameters["curveType"] = hint_ecc_mont(P1.curveID);
                    parameters["priv"] = P1.priv;
                    parameters["nonce"] = getBignum();

                    if ( getBool() ) {
                        parameters["cleartext"] = cryptofuzz::util::DecToHex(getBignum(true), (PRNG() % 64) * 2);
                    } else {
                        parameters["cleartext"] = getBuffer(PRNG() % 32);
                    }
                    parameters["nonceSource"] = PRNG() % 3;
                    parameters["digestType"] = getRandomDigest();

                    cryptofuzz::operation::Schnorr_Sign op(parameters);
                    op.Serialize(dsOut2);
                }
                break;
            case    CF_OPERATION("ECDSA_Verify"):
                {
                    parameters["modifier"] = getBuffer(PRNG() % 1024);

                    if ( Pool_CurveECDSASignature.Have() == true ) {
                        const auto P = Pool_CurveECDSASignature.Get();
                        parameters["curveType"] = hint_ecc_mont(P.curveID);

                        parameters["signature"]["pub"][0] = getBool() ? getBignum() : P.pub_x;
                        parameters["signature"]["pub"][1] = getBool() ? getBignum() : P.pub_y;

                        parameters["signature"]["signature"][0] = getBool() ? getBignum() : P.sig_r;
                        auto sigS = getBool() ? getBignum() : P.sig_y;

                        if ( getBool() ) {
                            /* Test ECDSA signature malleability */

                            const auto order = cryptofuzz::repository::ECC_CurveToOrder(P.curveID);
                            if ( order != std::nullopt ) {
                                const auto o = boost::multiprecision::cpp_int(*order);
                                const auto s = boost::multiprecision::cpp_int(sigS);
                                if ( o > s ) {
                                    sigS = boost::lexical_cast<std::string>(o - s);
                                }
                            }
                        }

                        parameters["signature"]["signature"][1] = sigS;
                        parameters["cleartext"] = P.cleartext;
                    } else {
                        parameters["curveType"] = hint_ecc_mont(getRandomCurve());

                        parameters["signature"]["pub"][0] = getBignum();
                        parameters["signature"]["pub"][1] = getBignum();

                        parameters["signature"]["signature"][0] = getBignum();
                        parameters["signature"]["signature"][1] = getBignum();

                        parameters["cleartext"] = cryptofuzz::util::DecToHex(getBignum(true), (PRNG() % 64) * 2);
                    }

                    parameters["digestType"] = getRandomDigest();

                    cryptofuzz::operation::ECDSA_Verify op(parameters);
                    op.Serialize(dsOut2);
                }
                break;
            case    CF_OPERATION("ECGDSA_Verify"):
                {
                    parameters["modifier"] = getBuffer(PRNG() % 1024);

                    if ( Pool_CurveECDSASignature.Have() == true ) {
                        const auto P = Pool_CurveECDSASignature.Get();
                        parameters["curveType"] = hint_ecc_mont(P.curveID);

                        parameters["signature"]["pub"][0] = getBool() ? getBignum() : P.pub_x;
                        parameters["signature"]["pub"][1] = getBool() ? getBignum() : P.pub_y;

                        parameters["signature"]["signature"][0] = getBool() ? getBignum() : P.sig_r;
                        auto sigS = getBool() ? getBignum() : P.sig_y;

                        if ( getBool() ) {
                            /* Test ECGDSA signature malleability */

                            const auto order = cryptofuzz::repository::ECC_CurveToOrder(P.curveID);
                            if ( order != std::nullopt ) {
                                const auto o = boost::multiprecision::cpp_int(*order);
                                const auto s = boost::multiprecision::cpp_int(sigS);
                                if ( o > s ) {
                                    sigS = boost::lexical_cast<std::string>(o - s);
                                }
                            }
                        }

                        parameters["signature"]["signature"][1] = sigS;
                        parameters["cleartext"] = P.cleartext;
                    } else {
                        parameters["curveType"] = hint_ecc_mont(getRandomCurve());

                        parameters["signature"]["pub"][0] = getBignum();
                        parameters["signature"]["pub"][1] = getBignum();

                        parameters["signature"]["signature"][0] = getBignum();
                        parameters["signature"]["signature"][1] = getBignum();

                        parameters["cleartext"] = cryptofuzz::util::DecToHex(getBignum(true), (PRNG() % 64) * 2);
                    }

                    parameters["digestType"] = getRandomDigest();

                    cryptofuzz::operation::ECGDSA_Verify op(parameters);
                    op.Serialize(dsOut2);
                }
                break;
            case    CF_OPERATION("ECRDSA_Verify"):
                {
                    parameters["modifier"] = getBuffer(PRNG() % 1024);

                    if ( Pool_CurveECDSASignature.Have() == true ) {
                        const auto P = Pool_CurveECDSASignature.Get();
                        parameters["curveType"] = hint_ecc_mont(P.curveID);

                        parameters["signature"]["pub"][0] = getBool() ? getBignum() : P.pub_x;
                        parameters["signature"]["pub"][1] = getBool() ? getBignum() : P.pub_y;

                        parameters["signature"]["signature"][0] = getBool() ? getBignum() : P.sig_r;
                        auto sigS = getBool() ? getBignum() : P.sig_y;

                        if ( getBool() ) {
                            /* Test ECRDSA signature malleability */

                            const auto order = cryptofuzz::repository::ECC_CurveToOrder(P.curveID);
                            if ( order != std::nullopt ) {
                                const auto o = boost::multiprecision::cpp_int(*order);
                                const auto s = boost::multiprecision::cpp_int(sigS);
                                if ( o > s ) {
                                    sigS = boost::lexical_cast<std::string>(o - s);
                                }
                            }
                        }

                        parameters["signature"]["signature"][1] = sigS;
                        parameters["cleartext"] = P.cleartext;
                    } else {
                        parameters["curveType"] = hint_ecc_mont(getRandomCurve());

                        parameters["signature"]["pub"][0] = getBignum();
                        parameters["signature"]["pub"][1] = getBignum();

                        parameters["signature"]["signature"][0] = getBignum();
                        parameters["signature"]["signature"][1] = getBignum();

                        parameters["cleartext"] = cryptofuzz::util::DecToHex(getBignum(true), (PRNG() % 64) * 2);
                    }

                    parameters["digestType"] = getRandomDigest();

                    cryptofuzz::operation::ECRDSA_Verify op(parameters);
                    op.Serialize(dsOut2);
                }
                break;
            case    CF_OPERATION("Schnorr_Verify"):
                {
                    parameters["modifier"] = getBuffer(PRNG() % 1024);

                    if ( Pool_CurveECDSASignature.Have() == true ) {
                        const auto P = Pool_CurveECDSASignature.Get();
                        parameters["curveType"] = hint_ecc_mont(P.curveID);

                        parameters["signature"]["pub"][0] = getBool() ? getBignum() : P.pub_x;
                        parameters["signature"]["pub"][1] = getBool() ? getBignum() : P.pub_y;

                        parameters["signature"]["signature"][0] = getBool() ? getBignum() : P.sig_r;
                        auto sigS = getBool() ? getBignum() : P.sig_y;

                        if ( getBool() ) {
                            /* Test Schnorr signature malleability */

                            const auto order = cryptofuzz::repository::ECC_CurveToOrder(P.curveID);
                            if ( order != std::nullopt ) {
                                const auto o = boost::multiprecision::cpp_int(*order);
                                const auto s = boost::multiprecision::cpp_int(sigS);
                                if ( o > s ) {
                                    sigS = boost::lexical_cast<std::string>(o - s);
                                }
                            }
                        }

                        parameters["signature"]["signature"][1] = sigS;
                        parameters["cleartext"] = P.cleartext;
                    } else {
                        parameters["curveType"] = hint_ecc_mont(getRandomCurve());

                        parameters["signature"]["pub"][0] = getBignum();
                        parameters["signature"]["pub"][1] = getBignum();

                        parameters["signature"]["signature"][0] = getBignum();
                        parameters["signature"]["signature"][1] = getBignum();

                        parameters["cleartext"] = cryptofuzz::util::DecToHex(getBignum(true), (PRNG() % 64) * 2);
                    }

                    parameters["digestType"] = getRandomDigest();

                    cryptofuzz::operation::Schnorr_Verify op(parameters);
                    op.Serialize(dsOut2);
                }
                break;
            case    CF_OPERATION("ECDSA_Recover"):
                {
                    parameters["modifier"] = getBuffer(PRNG() % 1024);

                    if ( getBool() && Pool_CurveECDSASignature.Have() == true ) {
                        const auto P = Pool_CurveECDSASignature.Get();
                        parameters["curveType"] = hint_ecc_mont(P.curveID);

                        parameters["signature"][0] = getBool() ? getBignum() : P.sig_r;
                        parameters["signature"][1] = getBool() ? getBignum() : P.sig_y;

                        if ( getBool() ) {
                            parameters["cleartext"] = P.cleartext;
                        } else {
                            parameters["cleartext"] = cryptofuzz::util::DecToHex(getBignum(true), (PRNG() % 64) * 2);
                        }
                    } else if ( getBool() && Pool_CurveECC_Point.Have() == true ) {
                        const auto P = Pool_CurveECC_Point.Get();
                        parameters["curveType"] = hint_ecc_mont(P.curveID);

                        parameters["signature"][0] = getBool() ? getBignum() : P.x;
                        parameters["signature"][1] = getBool() ? getBignum() : P.y;

                        parameters["cleartext"] = cryptofuzz::util::DecToHex(getBignum(true), (PRNG() % 64) * 2);
                    } else {
                        parameters["curveType"] = hint_ecc_mont(getRandomCurve());

                        parameters["signature"][0] = getBignum();
                        parameters["signature"][1] = getBignum();

                        parameters["cleartext"] = cryptofuzz::util::DecToHex(getBignum(true), (PRNG() % 64) * 2);
                    }

                    parameters["id"] = PRNG() % 4;
                    parameters["digestType"] = getRandomDigest();

                    cryptofuzz::operation::ECDSA_Recover op(parameters);
                    op.Serialize(dsOut2);
                }
            case    CF_OPERATION("ECC_GenerateKeyPair"):
                {
                    parameters["modifier"] = getBuffer(PRNG() % 128);
                    parameters["curveType"] = hint_ecc_mont(getRandomCurve());

                    cryptofuzz::operation::ECC_GenerateKeyPair op(parameters);
                    op.Serialize(dsOut2);
                }
                break;
            case    CF_OPERATION("ECIES_Encrypt"):
            case    CF_OPERATION("ECIES_Decrypt"):
                {
                    parameters["modifier"] = getBuffer(PRNG() % 128);
                    if ( operation == CF_OPERATION("ECIES_Encrypt") ) {
                        parameters["cleartext"] = getBuffer(PRNG() % 1024);
                    } else {
                        parameters["ciphertext"] = getBuffer(PRNG() % 1024);
                    }
                    //parameters["cipherType"] = getRandomCipher();
                    parameters["cipherType"] = CF_CIPHER("AES_128_CBC");
                    parameters["iv_enabled"] = false;

                    parameters["priv"] = getBignum();

                    if ( Pool_CurveKeypair.Have() && getBool() == true ) {
                        const auto P = Pool_CurveKeypair.Get();

                        parameters["curveType"] = hint_ecc_mont(P.curveID);
                        parameters["pub_x"] = P.pub_x;
                        parameters["pub_y"] = P.pub_y;

                        if ( Pool_CurvePrivkey.Have() && getBool() == true ) {
                            const auto P2 = Pool_CurvePrivkey.Get();
                            if ( P2.curveID == P.curveID ) {
                                parameters["priv"] = P2.priv;
                            }
                        }
                    } else {
                        parameters["curveType"] = hint_ecc_mont(getRandomCurve());
                        parameters["pub_x"] = getBignum();
                        parameters["pub_y"] = getBignum();
                    }

                    if ( operation == CF_OPERATION("ECIES_Encrypt") ) {
                        cryptofuzz::operation::ECIES_Encrypt op(parameters);
                        op.Serialize(dsOut2);
                    } else {
                        cryptofuzz::operation::ECIES_Decrypt op(parameters);
                        op.Serialize(dsOut2);
                    }
                }
                break;
            case    CF_OPERATION("ECC_Point_Add"):
                {
                    parameters["modifier"] = "";

                    if ( Pool_CurveECC_Point.Have() == true ) {
                        const auto P = Pool_CurveECC_Point.Get();
                        parameters["curveType"] = hint_ecc_mont(P.curveID);

                        parameters["a_x"] = getBool() ? getBignum() : P.x;
                        parameters["a_y"] = getBool() ? getBignum() : P.y;
                    } else {
                        parameters["curveType"] = hint_ecc_mont(getRandomCurve());

                        parameters["a_x"] = getBignum();
                        parameters["a_y"] = getBignum();
                    }

                    if ( Pool_CurveECC_Point.Have() == true ) {
                        const auto P = Pool_CurveECC_Point.Get();
                        parameters["curveType"] = hint_ecc_mont(P.curveID);

                        parameters["b_x"] = getBool() ? getBignum() : P.x;
                        parameters["b_y"] = getBool() ? getBignum() : P.y;
                    } else {
                        parameters["curveType"] = hint_ecc_mont(getRandomCurve());

                        parameters["b_x"] = getBignum();
                        parameters["b_y"] = getBignum();
                    }

                    cryptofuzz::operation::ECC_Point_Add op(parameters);
                    op.Serialize(dsOut2);

                    generateECCPoint();
                }
                break;
            case    CF_OPERATION("ECC_Point_Mul"):
                {
                    parameters["modifier"] = "";

                    if ( Pool_CurveECC_Point.Have() == true ) {
                        const auto P = Pool_CurveECC_Point.Get();
                        parameters["curveType"] = hint_ecc_mont(P.curveID);

                        parameters["a_x"] = getBool() ? getBignum() : P.x;
                        parameters["a_y"] = getBool() ? getBignum() : P.y;
                    } else {
                        parameters["curveType"] = hint_ecc_mont(getRandomCurve());

                        parameters["a_x"] = getBignum();
                        parameters["a_y"] = getBignum();
                    }

                    parameters["b"] = getBignum();

                    cryptofuzz::operation::ECC_Point_Mul op(parameters);
                    op.Serialize(dsOut2);

                    generateECCPoint();
                }
                break;
            case    CF_OPERATION("ECC_Point_Neg"):
                {
                    parameters["modifier"] = "";

                    if ( Pool_CurveECC_Point.Have() == true ) {
                        const auto P = Pool_CurveECC_Point.Get();
                        parameters["curveType"] = hint_ecc_mont(P.curveID);

                        parameters["a_x"] = getBool() ? getBignum() : P.x;
                        parameters["a_y"] = getBool() ? getBignum() : P.y;
                    } else {
                        parameters["curveType"] = hint_ecc_mont(getRandomCurve());

                        parameters["a_x"] = getBignum();
                        parameters["a_y"] = getBignum();
                    }

                    cryptofuzz::operation::ECC_Point_Neg op(parameters);
                    op.Serialize(dsOut2);

                    generateECCPoint();
                }
                break;
            case    CF_OPERATION("ECC_Point_Dbl"):
                {
                    parameters["modifier"] = "";

                    if ( Pool_CurveECC_Point.Have() == true ) {
                        const auto P = Pool_CurveECC_Point.Get();
                        parameters["curveType"] = hint_ecc_mont(P.curveID);

                        parameters["a_x"] = getBool() ? getBignum() : P.x;
                        parameters["a_y"] = getBool() ? getBignum() : P.y;
                    } else {
                        parameters["curveType"] = hint_ecc_mont(getRandomCurve());

                        parameters["a_x"] = getBignum();
                        parameters["a_y"] = getBignum();
                    }

                    cryptofuzz::operation::ECC_Point_Dbl op(parameters);
                    op.Serialize(dsOut2);

                    generateECCPoint();
                }
                break;
            case    CF_OPERATION("KDF_SCRYPT"):
                {
                    size_t numParts = 0;

                    numParts++; /* modifier */
                    numParts++; /* password */
                    numParts++; /* salt */

                    const auto lengths = SplitLength(maxSize - 64, numParts);

                    parameters["modifier"] = getBuffer(lengths[0]);
                    parameters["password"] = getBuffer(lengths[1]);
                    parameters["salt"] = getBuffer(lengths[2]);
                    parameters["N"] = PRNG() % 5;
                    parameters["r"] = PRNG() % 9;
                    parameters["p"] = PRNG() % 5;
                    parameters["keySize"] = PRNG() % 1024;

                    cryptofuzz::operation::KDF_SCRYPT op(parameters);
                    op.Serialize(dsOut2);
                }
                break;
            case    CF_OPERATION("KDF_HKDF"):
                {
                    size_t numParts = 0;

                    numParts++; /* modifier */
                    numParts++; /* password */
                    numParts++; /* salt */
                    numParts++; /* info */

                    const auto lengths = SplitLength(maxSize - 64, numParts);

                    parameters["modifier"] = getBuffer(lengths[0]);
                    parameters["password"] = getBuffer(lengths[1]);
                    parameters["salt"] = getBuffer(lengths[2]);
                    parameters["info"] = getBuffer(lengths[3]);
                    parameters["keySize"] = PRNG() % 17000;
                    parameters["digestType"] = getRandomDigest();

                    cryptofuzz::operation::KDF_HKDF op(parameters);
                    op.Serialize(dsOut2);
                }
                break;
            case    CF_OPERATION("KDF_TLS1_PRF"):
                {
                    size_t numParts = 0;

                    numParts++; /* modifier */
                    numParts++; /* secret */
                    numParts++; /* seed */

                    const auto lengths = SplitLength(maxSize - 64, numParts);

                    parameters["modifier"] = getBuffer(lengths[0]);
                    parameters["secret"] = getBuffer(lengths[1]);
                    parameters["seed"] = getBuffer(lengths[2]);
                    parameters["keySize"] = PRNG() % 1024;
                    parameters["digestType"] = getRandomDigest();

                    cryptofuzz::operation::KDF_TLS1_PRF op(parameters);
                    op.Serialize(dsOut2);
                }
                break;
            case    CF_OPERATION("KDF_PBKDF"):
                {
                    size_t numParts = 0;

                    numParts++; /* modifier */
                    numParts++; /* password */
                    numParts++; /* salt */

                    const auto lengths = SplitLength(maxSize - 64, numParts);

                    parameters["modifier"] = getBuffer(lengths[0]);
                    parameters["password"] = getBuffer(lengths[1]);
                    parameters["salt"] = getBuffer(lengths[2]);
                    parameters["iterations"] = PRNG() % 5;
                    parameters["keySize"] = PRNG() % 1024;
                    parameters["digestType"] = getRandomDigest();

                    cryptofuzz::operation::KDF_PBKDF op(parameters);
                    op.Serialize(dsOut2);
                }
                break;
            case    CF_OPERATION("KDF_PBKDF1"):
                {
                    size_t numParts = 0;

                    numParts++; /* modifier */
                    numParts++; /* password */
                    numParts++; /* salt */

                    const auto lengths = SplitLength(maxSize - 64, numParts);

                    parameters["modifier"] = getBuffer(lengths[0]);
                    parameters["password"] = getBuffer(lengths[1]);
                    parameters["salt"] = getBuffer(lengths[2]);
                    parameters["iterations"] = PRNG() % 5;
                    parameters["keySize"] = PRNG() % 1024;
                    parameters["digestType"] = getRandomDigest();

                    cryptofuzz::operation::KDF_PBKDF op(parameters);
                    op.Serialize(dsOut2);
                }
                break;
            case    CF_OPERATION("KDF_PBKDF2"):
                {
                    size_t numParts = 0;

                    numParts++; /* modifier */
                    numParts++; /* password */
                    numParts++; /* salt */

                    const auto lengths = SplitLength(maxSize - 64, numParts);

                    parameters["modifier"] = getBuffer(lengths[0]);
                    parameters["password"] = getBuffer(lengths[1]);
                    parameters["salt"] = getBuffer(lengths[2]);
                    parameters["iterations"] = PRNG() % 5;
                    parameters["keySize"] = PRNG() % 1024;
                    parameters["digestType"] = getRandomDigest();

                    cryptofuzz::operation::KDF_PBKDF2 op(parameters);
                    op.Serialize(dsOut2);
                }
                break;
            case    CF_OPERATION("KDF_ARGON2"):
                {
                    size_t numParts = 0;

                    numParts++; /* modifier */
                    numParts++; /* password */
                    numParts++; /* salt */

                    const auto lengths = SplitLength(maxSize - 64, numParts);

                    parameters["modifier"] = getBuffer(lengths[0]);
                    parameters["password"] = getBuffer(lengths[1]);
                    parameters["salt"] = getBuffer(lengths[2]);
                    parameters["type"] = PRNG() % 3;
                    parameters["threads"] = PRNG() % 256;
                    parameters["memory"] = PRNG() % (64*1024);
                    parameters["iterations"] = PRNG() % 3;
                    parameters["keySize"] = PRNG() % 1024;

                    cryptofuzz::operation::KDF_ARGON2 op(parameters);
                    op.Serialize(dsOut2);
                }
                break;
            case    CF_OPERATION("KDF_SSH"):
                {
                    size_t numParts = 0;

                    numParts++; /* modifier */
                    numParts++; /* key */
                    numParts++; /* xcghash */
                    numParts++; /* session_id */

                    const auto lengths = SplitLength(maxSize - 64, numParts);

                    parameters["modifier"] = getBuffer(lengths[0]);
                    parameters["key"] = getBuffer(lengths[1]);
                    parameters["xcghash"] = getBuffer(lengths[2]);
                    parameters["session_id"] = getBuffer(lengths[3]);
                    parameters["type"] = getBuffer(1);
                    parameters["keySize"] = PRNG() % 1024;
                    parameters["digestType"] = getRandomDigest();

                    cryptofuzz::operation::KDF_SSH op(parameters);
                    op.Serialize(dsOut2);
                }
                break;
            case    CF_OPERATION("KDF_X963"):
                {
                    size_t numParts = 0;

                    numParts++; /* modifier */
                    numParts++; /* secret */
                    numParts++; /* info */

                    const auto lengths = SplitLength(maxSize - 64, numParts);

                    parameters["modifier"] = getBuffer(lengths[0]);
                    parameters["secret"] = getBuffer(lengths[1]);
                    parameters["info"] = getBuffer(lengths[2]);
                    parameters["keySize"] = PRNG() % 1024;
                    parameters["digestType"] = getRandomDigest();

                    cryptofuzz::operation::KDF_X963 op(parameters);
                    op.Serialize(dsOut2);
                }
                break;
            case    CF_OPERATION("KDF_SP_800_108"):
                {
                    size_t numParts = 0;

                    numParts++; /* modifier */
                    numParts++; /* secret */
                    numParts++; /* salt */
                    numParts++; /* label */

                    const auto lengths = SplitLength(maxSize - 64, numParts);

                    if ( getBool() == true ) {
                        /* MAC = HMAC */
                        parameters["mech"]["mode"] = true;
                        parameters["mech"]["type"] = getRandomDigest();
                    } else {
                        /* MAC = CMAC */
                        parameters["mech"]["mode"] = false;
                        parameters["mech"]["type"] = getRandomCipher();
                    }

                    parameters["modifier"] = getBuffer(lengths[0]);
                    parameters["secret"] = getBuffer(lengths[1]);
                    parameters["salt"] = getBuffer(lengths[2]);
                    parameters["label"] = getBuffer(lengths[3]);
                    parameters["mode"] = PRNG() % 3;
                    parameters["keySize"] = PRNG() % 17000;

                    cryptofuzz::operation::KDF_SP_800_108 op(parameters);
                    op.Serialize(dsOut2);
                }
                break;
            case    CF_OPERATION("DH_GenerateKeyPair"):
                {
                    parameters["modifier"] = getBuffer(PRNG() % 1000);
                    parameters["prime"] = getBignum();
                    parameters["base"] = getBignum();

                    cryptofuzz::operation::DH_GenerateKeyPair op(parameters);
                    op.Serialize(dsOut2);
                }
                break;
            case    CF_OPERATION("DH_Derive"):
                {
                    parameters["modifier"] = getBuffer(PRNG() % 1000);
                    parameters["prime"] = getBignum();
                    parameters["base"] = getBignum();
                    if ( Pool_DH_PublicKey.Have() && getBool() == true ) {
                        parameters["pub"] = Pool_DH_PublicKey.Get();
                    } else {
                        parameters["pub"] = getBignum();
                    }

                    if ( Pool_DH_PrivateKey.Have() && getBool() == true ) {
                        parameters["priv"] = Pool_DH_PrivateKey.Get();
                    } else {
                        parameters["priv"] = getBignum();
                    }

                    cryptofuzz::operation::DH_Derive op(parameters);
                    op.Serialize(dsOut2);
                }
                break;
            case    CF_OPERATION("BLS_PrivateToPublic"):
                {
                    parameters["modifier"] = getBuffer(PRNG() % 1000);
                    parameters["curveType"] = hint_ecc_mont(CF_ECC_CURVE("BLS12_381"));

                    parameters["priv"] = getBignum();

                    cryptofuzz::operation::BLS_PrivateToPublic op(parameters);
                    op.Serialize(dsOut2);
                }
                break;
            case    CF_OPERATION("BLS_PrivateToPublic_G2"):
                {
                    parameters["modifier"] = getBuffer(PRNG() % 1000);
                    parameters["curveType"] = hint_ecc_mont(CF_ECC_CURVE("BLS12_381"));

                    parameters["priv"] = getBignum();

                    cryptofuzz::operation::BLS_PrivateToPublic_G2 op(parameters);
                    op.Serialize(dsOut2);
                }
                break;
            case    CF_OPERATION("BLS_Sign"):
                {
                    parameters["modifier"] = getBuffer(PRNG() % 1000);
                    parameters["curveType"] = hint_ecc_mont(CF_ECC_CURVE("BLS12_381"));
                    const auto hashOrPoint = getBool();
                    //const auto hashOrPoint = false;
                    parameters["hashOrPoint"] = hashOrPoint;
                    if ( hashOrPoint == true ) {
                        //parameters["cleartext"] = getBuffer(PRNG() % 32);
                        parameters["cleartext"] = cryptofuzz::util::DecToHex(getBignum(true), (PRNG() % 64) * 2);
                        parameters["point_v"] = "";
                        parameters["point_w"] = "";
                        parameters["point_x"] = "";
                        parameters["point_y"] = "";
                    } else {
                        if ( getBool() && Pool_CurveBLSG2.Have() == true ) {
                            const auto P = Pool_CurveBLSG2.Get();
                            parameters["point_v"] = GET_OR_BIGNUM(P.g2_v);
                            parameters["point_w"] = GET_OR_BIGNUM(P.g2_w);
                            parameters["point_x"] = GET_OR_BIGNUM(P.g2_x);
                            parameters["point_y"] = GET_OR_BIGNUM(P.g2_y);
                        } else {
                            parameters["point_v"] = getBignum();
                            parameters["point_w"] = getBignum();
                            parameters["point_x"] = getBignum();
                            parameters["point_y"] = getBignum();
                        }

                        parameters["cleartext"] = "";
                    }
                    parameters["dest"] = getBool() ? getBuffer(PRNG() % 512) : get_BLS_predefined_DST();
                    parameters["aug"] = "";
                    parameters["priv"] = getBignum();

                    cryptofuzz::operation::BLS_Sign op(parameters);
                    op.Serialize(dsOut2);
                }
                break;
            case    CF_OPERATION("BLS_Verify"):
                {
                    parameters["modifier"] = getBuffer(PRNG() % 1000);

                    if ( Pool_CurveBLSSignature.Have() == true ) {
                        const auto P = Pool_CurveBLSSignature.Get();

                        parameters["curveType"] = hint_ecc_mont(P.curveID);
                        parameters["hashOrPoint"] = P.hashOrPoint;
                        parameters["point_v"] = GET_OR_BIGNUM(P.point_v);
                        parameters["point_w"] = GET_OR_BIGNUM(P.point_w);
                        parameters["point_x"] = GET_OR_BIGNUM(P.point_x);
                        parameters["point_y"] = GET_OR_BIGNUM(P.point_y);
                        parameters["cleartext"] = P.cleartext;
                        parameters["dest"] = P.dest;
                        parameters["aug"] = P.aug;
                        parameters["pub_x"] = GET_OR_BIGNUM(P.pub_x);
                        parameters["pub_y"] = GET_OR_BIGNUM(P.pub_y);
                        parameters["sig_v"] = GET_OR_BIGNUM(P.sig_v);
                        parameters["sig_w"] = GET_OR_BIGNUM(P.sig_w);
                        parameters["sig_x"] = GET_OR_BIGNUM(P.sig_x);
                        parameters["sig_y"] = GET_OR_BIGNUM(P.sig_y);
                    } else {
                        parameters["curveType"] = hint_ecc_mont(CF_ECC_CURVE("BLS12_381"));
                        const auto hashOrPoint = getBool();
                        parameters["hashOrPoint"] = hashOrPoint;
                        if ( hashOrPoint == true ) {
                            parameters["cleartext"] = getBuffer(PRNG() % 32);
                            parameters["point_v"] = "";
                            parameters["point_w"] = "";
                            parameters["point_x"] = "";
                            parameters["point_y"] = "";
                        } else {
                            parameters["point_v"] = getBignum();
                            parameters["point_w"] = getBignum();
                            parameters["point_x"] = getBignum();
                            parameters["point_y"] = getBignum();
                            parameters["cleartext"] = "";
                        }
                        parameters["dest"] = getBool() ? getBuffer(PRNG() % 512) : get_BLS_predefined_DST();
                        parameters["pub_x"] = getBignum();
                        parameters["pub_y"] = getBignum();
                        parameters["sig_v"] = getBignum();
                        parameters["sig_w"] = getBignum();
                        parameters["sig_x"] = getBignum();
                        parameters["sig_y"] = getBignum();
                    }

                    cryptofuzz::operation::BLS_Verify op(parameters);
                    op.Serialize(dsOut2);
                }
                break;
            case    CF_OPERATION("BLS_BatchSign"):
                {
                    parameters["modifier"] = "";

                    //const size_t num = PRNG() % 100;
                    //const size_t num = (PRNG() % 50) + 30;
                    const size_t num = (PRNG() % 8) + 1;

                    parameters["bf"] = nlohmann::json::array();

                    for (size_t i = 0; i < num; i++) {
                        const auto P = Pool_CurveBLSG1.Get();

                        nlohmann::json p;

                        p["priv"] = getBignum();
                        p["g1_x"] = P.g1_x;
                        p["g1_y"] = P.g1_y;

                        parameters["bf"].push_back(p);
                    }

                    cryptofuzz::operation::BLS_BatchSign op(parameters);
                    op.Serialize(dsOut2);

                    generateECCPoint();
                }
                break;
            case    CF_OPERATION("BLS_BatchVerify"):
                {
                    parameters["modifier"] = "";
                    parameters["dest"] = get_BLS_predefined_DST();

                    std::vector<
                        std::pair<
                            std::array<std::string, 2>,
                            std::array<std::string, 4>
                        >
                    > points;

                    if ( Pool_BLS_BatchSignature.Have() == true ) {
                        const auto sig = Pool_BLS_BatchSignature.Get();

                        for (const auto& mp : sig.msgpub) {
                            std::array<std::string, 2> g1;
                            std::array<std::string, 4> g2;

                            switch ( PRNG() % 3 ) {
                                case    0:
                                    {
                                        const auto P = Pool_CurveBLSG1.Get();
                                        g1 = {P.g1_x, P.g1_y};
                                    }
                                    break;
                                case    1:
                                    g1 = {mp.first.g1_x, mp.first.g1_y};
                                    break;
                                case    2:
                                    g1 = {getBignum(), getBignum()};
                                    break;
                            }

                            if ( (PRNG()%3) == 0 ) {
                                const auto P2 = Pool_CurveBLSG2.Get();
                                g2 = {P2.g2_v, P2.g2_w, P2.g2_x, P2.g2_y};
                            } else {
                                g2 = {mp.second.g2_v, mp.second.g2_w, mp.second.g2_x, mp.second.g2_y};
                            }

                            points.push_back({g1, g2});
                        }

                        parameters["bf"] = nlohmann::json::array();

                        std::shuffle(std::begin(points), std::end(points), rng);

                        for (const auto& p : points) {
                            nlohmann::json cur;
                            cur["g1_x"] = p.first[0];
                            cur["g1_y"] = p.first[1];

                            cur["g2_v"] = p.second[0];
                            cur["g2_w"] = p.second[1];
                            cur["g2_x"] = p.second[2];
                            cur["g2_y"] = p.second[3];
                            parameters["bf"].push_back(cur);
                        }

                        cryptofuzz::operation::BLS_BatchVerify op(parameters);
                        op.Serialize(dsOut2);
                    } else {
                        goto end;
                    }
                }
                break;
            case    CF_OPERATION("BLS_IsG1OnCurve"):
                {
                    parameters["modifier"] = getBuffer(PRNG() % 1000);
                    parameters["curveType"] = hint_ecc_mont(CF_ECC_CURVE("BLS12_381"));

                    if ( getBool() && Pool_CurveBLSG1.Have() == true ) {
                        const auto P = Pool_CurveBLSG1.Get();
                        parameters["g1_x"] = GET_OR_BIGNUM(P.g1_x);
                        parameters["g1_y"] = GET_OR_BIGNUM(P.g1_y);
                    } else {
                        parameters["g1_x"] = getBignum();
                        parameters["g1_y"] = getBignum();
                    }

                    cryptofuzz::operation::BLS_IsG1OnCurve op(parameters);
                    op.Serialize(dsOut2);

                    generateECCPoint();
                }
                break;
            case    CF_OPERATION("BLS_IsG2OnCurve"):
                {
                    parameters["modifier"] = getBuffer(PRNG() % 1000);
                    parameters["curveType"] = hint_ecc_mont(CF_ECC_CURVE("BLS12_381"));

                    if ( getBool() && Pool_CurveBLSG2.Have() == true ) {
                        const auto P = Pool_CurveBLSG2.Get();
                        parameters["g2_v"] = GET_OR_BIGNUM(P.g2_v);
                        parameters["g2_w"] = GET_OR_BIGNUM(P.g2_w);
                        parameters["g2_x"] = GET_OR_BIGNUM(P.g2_x);
                        parameters["g2_y"] = GET_OR_BIGNUM(P.g2_y);
                    } else {
                        parameters["g2_v"] = getBignum();
                        parameters["g2_w"] = getBignum();
                        parameters["g2_x"] = getBignum();
                        parameters["g2_y"] = getBignum();
                    }

                    cryptofuzz::operation::BLS_IsG2OnCurve op(parameters);
                    op.Serialize(dsOut2);
                }
                break;
            case    CF_OPERATION("BLS_GenerateKeyPair"):
                {
                    parameters["modifier"] = getBuffer(PRNG() % 1000);
                    parameters["curveType"] = hint_ecc_mont(CF_ECC_CURVE("BLS12_381"));
                    parameters["ikm"] = getBuffer(PRNG() % 512);
                    parameters["info"] = getBuffer(PRNG() % 512);

                    cryptofuzz::operation::BLS_GenerateKeyPair op(parameters);
                    op.Serialize(dsOut2);
                }
                break;
            case    CF_OPERATION("BLS_Decompress_G1"):
                {
                    parameters["modifier"] = getBuffer(PRNG() % 1000);
                    parameters["curveType"] = hint_ecc_mont(CF_ECC_CURVE("BLS12_381"));
                    parameters["compressed"] = getBignum();

                    cryptofuzz::operation::BLS_Decompress_G1 op(parameters);
                    op.Serialize(dsOut2);
                }
                break;
            case    CF_OPERATION("BLS_Compress_G1"):
                {
                    parameters["modifier"] = getBuffer(PRNG() % 1000);
                    parameters["curveType"] = hint_ecc_mont(CF_ECC_CURVE("BLS12_381"));

                    if ( getBool() && Pool_CurveBLSG1.Have() == true ) {
                        const auto P = Pool_CurveBLSG1.Get();
                        parameters["g1_x"] = GET_OR_BIGNUM(P.g1_x);
                        parameters["g1_y"] = GET_OR_BIGNUM(P.g1_y);
                    } else {
                        parameters["g1_x"] = getBignum();
                        parameters["g1_y"] = getBignum();
                    }

                    cryptofuzz::operation::BLS_Compress_G1 op(parameters);
                    op.Serialize(dsOut2);

                    generateECCPoint();
                }
                break;
            case    CF_OPERATION("BLS_Decompress_G2"):
                {
                    parameters["modifier"] = getBuffer(PRNG() % 1000);
                    parameters["curveType"] = hint_ecc_mont(CF_ECC_CURVE("BLS12_381"));
                    parameters["g1_x"] = getBignum();
                    parameters["g1_y"] = getBignum();

                    cryptofuzz::operation::BLS_Decompress_G2 op(parameters);
                    op.Serialize(dsOut2);
                }
                break;
            case    CF_OPERATION("BLS_Compress_G2"):
                {
                    parameters["modifier"] = getBuffer(PRNG() % 1000);
                    parameters["curveType"] = hint_ecc_mont(CF_ECC_CURVE("BLS12_381"));

                    if ( getBool() && Pool_CurveBLSG2.Have() == true ) {
                        const auto P = Pool_CurveBLSG2.Get();
                        parameters["g2_v"] = GET_OR_BIGNUM(P.g2_v);
                        parameters["g2_w"] = GET_OR_BIGNUM(P.g2_w);
                        parameters["g2_x"] = GET_OR_BIGNUM(P.g2_x);
                        parameters["g2_y"] = GET_OR_BIGNUM(P.g2_y);
                    } else {
                        parameters["g2_v"] = getBignum();
                        parameters["g2_w"] = getBignum();
                        parameters["g2_x"] = getBignum();
                        parameters["g2_y"] = getBignum();
                    }

                    cryptofuzz::operation::BLS_Compress_G2 op(parameters);
                    op.Serialize(dsOut2);
                }
                break;
            case    CF_OPERATION("BLS_HashToG1"):
                {
                    parameters["modifier"] = getBuffer(PRNG() % 1000);
                    parameters["curveType"] = hint_ecc_mont(CF_ECC_CURVE("BLS12_381"));
                    parameters["cleartext"] = getBuffer(PRNG() % 1024);
                    parameters["dest"] = getBool() ? getBuffer(PRNG() % 512) : get_BLS_predefined_DST();

                    parameters["aug"] = getBuffer(PRNG() % 1024);

                    cryptofuzz::operation::BLS_HashToG1 op(parameters);
                    op.Serialize(dsOut2);
                }
                break;
            case    CF_OPERATION("BLS_HashToG2"):
                {
                    parameters["modifier"] = getBuffer(PRNG() % 1000);
                    parameters["curveType"] = hint_ecc_mont(CF_ECC_CURVE("BLS12_381"));
                    parameters["cleartext"] = getBuffer(PRNG() % 1024);
                    parameters["dest"] = getBool() ? getBuffer(PRNG() % 512) : get_BLS_predefined_DST();
                    parameters["aug"] = getBuffer(PRNG() % 1024);

                    cryptofuzz::operation::BLS_HashToG2 op(parameters);
                    op.Serialize(dsOut2);
                }
                break;
            case    CF_OPERATION("BLS_MapToG1"):
                {
                    parameters["modifier"] = "";
                    parameters["curveType"] = hint_ecc_mont(CF_ECC_CURVE("BLS12_381"));
                    parameters["u"] = getBignum();
                    parameters["v"] = getBignum();

                    cryptofuzz::operation::BLS_MapToG1 op(parameters);
                    op.Serialize(dsOut2);
                }
                break;
            case    CF_OPERATION("BLS_MapToG2"):
                {
                    parameters["modifier"] = "";
                    parameters["curveType"] = hint_ecc_mont(CF_ECC_CURVE("BLS12_381"));
                    parameters["u"][0] = getBignum();
                    parameters["u"][1] = getBignum();
                    parameters["v"][0] = getBignum();
                    parameters["v"][1] = getBignum();

                    cryptofuzz::operation::BLS_MapToG2 op(parameters);
                    op.Serialize(dsOut2);
                }
                break;
            case    CF_OPERATION("BLS_Pairing"):
                {
                    parameters["modifier"] = "";
                    parameters["curveType"] = hint_ecc_mont(CF_ECC_CURVE("BLS12_381"));

                    if ( getBool() && Pool_CurveBLSG1.Have() == true ) {
                        const auto P = Pool_CurveBLSG1.Get();
                        parameters["g1_x"] = GET_OR_BIGNUM(P.g1_x);
                        parameters["g1_y"] = GET_OR_BIGNUM(P.g1_y);
                    } else {
                        parameters["g1_x"] = getBignum();
                        parameters["g1_y"] = getBignum();
                    }

                    if ( getBool() && Pool_CurveBLSG2.Have() == true ) {
                        const auto P = Pool_CurveBLSG2.Get();
                        parameters["g2_v"] = GET_OR_BIGNUM(P.g2_v);
                        parameters["g2_w"] = GET_OR_BIGNUM(P.g2_w);
                        parameters["g2_x"] = GET_OR_BIGNUM(P.g2_x);
                        parameters["g2_y"] = GET_OR_BIGNUM(P.g2_y);
                    } else {
                        parameters["g2_v"] = getBignum();
                        parameters["g2_w"] = getBignum();
                        parameters["g2_x"] = getBignum();
                        parameters["g2_y"] = getBignum();
                    }

                    cryptofuzz::operation::BLS_Pairing op(parameters);
                    op.Serialize(dsOut2);

                    generateECCPoint();
                }
                break;
            case    CF_OPERATION("BLS_MillerLoop"):
                {
                    parameters["modifier"] = "";
                    parameters["curveType"] = hint_ecc_mont(CF_ECC_CURVE("BLS12_381"));

                    if ( getBool() && Pool_CurveBLSG1.Have() == true ) {
                        const auto P = Pool_CurveBLSG1.Get();
                        parameters["g1_x"] = GET_OR_BIGNUM(P.g1_x);
                        parameters["g1_y"] = GET_OR_BIGNUM(P.g1_y);
                    } else {
                        parameters["g1_x"] = getBignum();
                        parameters["g1_y"] = getBignum();
                    }

                    if ( getBool() && Pool_CurveBLSG2.Have() == true ) {
                        const auto P = Pool_CurveBLSG2.Get();
                        parameters["g2_v"] = GET_OR_BIGNUM(P.g2_v);
                        parameters["g2_w"] = GET_OR_BIGNUM(P.g2_w);
                        parameters["g2_x"] = GET_OR_BIGNUM(P.g2_x);
                        parameters["g2_y"] = GET_OR_BIGNUM(P.g2_y);
                    } else {
                        parameters["g2_v"] = getBignum();
                        parameters["g2_w"] = getBignum();
                        parameters["g2_x"] = getBignum();
                        parameters["g2_y"] = getBignum();
                    }

                    cryptofuzz::operation::BLS_MillerLoop op(parameters);
                    op.Serialize(dsOut2);

                    generateECCPoint();
                }
                break;
            case    CF_OPERATION("BLS_FinalExp"):
                {
                    parameters["modifier"] = "";
                    parameters["curveType"] = hint_ecc_mont(CF_ECC_CURVE("BLS12_381"));

                    if ( Pool_Fp12.Have() && getBool() == true ) {
                        const auto Fp12 = Pool_Fp12.Get();

                        parameters["fp12"][0] = Fp12.bn1;
                        parameters["fp12"][1] = Fp12.bn2;
                        parameters["fp12"][2] = Fp12.bn3;
                        parameters["fp12"][3] = Fp12.bn4;
                        parameters["fp12"][4] = Fp12.bn5;
                        parameters["fp12"][5] = Fp12.bn6;
                        parameters["fp12"][6] = Fp12.bn7;
                        parameters["fp12"][7] = Fp12.bn8;
                        parameters["fp12"][8] = Fp12.bn9;
                        parameters["fp12"][9] = Fp12.bn10;
                        parameters["fp12"][10] = Fp12.bn11;
                        parameters["fp12"][11] = Fp12.bn12;
                    } else {
                        parameters["fp12"][0] = getBignum();
                        parameters["fp12"][1] = getBignum();
                        parameters["fp12"][2] = getBignum();
                        parameters["fp12"][3] = getBignum();
                        parameters["fp12"][4] = getBignum();
                        parameters["fp12"][5] = getBignum();
                        parameters["fp12"][6] = getBignum();
                        parameters["fp12"][7] = getBignum();
                        parameters["fp12"][8] = getBignum();
                        parameters["fp12"][9] = getBignum();
                        parameters["fp12"][10] = getBignum();
                        parameters["fp12"][11] = getBignum();
                    }

                    cryptofuzz::operation::BLS_FinalExp op(parameters);
                    op.Serialize(dsOut2);
                }
                break;
            case    CF_OPERATION("BLS_G1_Add"):
                {
                    parameters["modifier"] = getBuffer(PRNG() % 1000);
                    parameters["curveType"] = hint_ecc_mont(CF_ECC_CURVE("BLS12_381"));

                    if ( getBool() && Pool_CurveBLSG1.Have() == true ) {
                        const auto P = Pool_CurveBLSG1.Get();
                        parameters["a_x"] = GET_OR_BIGNUM(P.g1_x);
                        parameters["a_y"] = GET_OR_BIGNUM(P.g1_y);
                    } else {
                        parameters["a_x"] = getBignum();
                        parameters["a_y"] = getBignum();
                    }

                    if ( getBool() && Pool_CurveBLSG1.Have() == true ) {
                        const auto P = Pool_CurveBLSG1.Get();
                        parameters["b_x"] = GET_OR_BIGNUM(P.g1_x);
                        parameters["b_y"] = GET_OR_BIGNUM(P.g1_y);
                    } else {
                        parameters["b_x"] = getBignum();
                        parameters["b_y"] = getBignum();
                    }

                    cryptofuzz::operation::BLS_G1_Add op(parameters);
                    op.Serialize(dsOut2);

                    generateECCPoint();
                }
                break;
            case    CF_OPERATION("BLS_G1_Mul"):
                {
                    parameters["modifier"] = getBuffer(PRNG() % 1000);
                    parameters["curveType"] = hint_ecc_mont(CF_ECC_CURVE("BLS12_381"));

                    if ( getBool() && Pool_CurveBLSG1.Have() == true ) {
                        const auto P = Pool_CurveBLSG1.Get();
                        parameters["a_x"] = GET_OR_BIGNUM(P.g1_x);
                        parameters["a_y"] = GET_OR_BIGNUM(P.g1_y);
                    } else {
                        parameters["a_x"] = getBignum();
                        parameters["a_y"] = getBignum();
                    }

                    parameters["b"] = getBignum();

                    cryptofuzz::operation::BLS_G1_Mul op(parameters);
                    op.Serialize(dsOut2);

                    generateECCPoint();
                }
                break;
            case    CF_OPERATION("BLS_G1_IsEq"):
                {
                    parameters["modifier"] = getBuffer(PRNG() % 1000);
                    parameters["curveType"] = hint_ecc_mont(CF_ECC_CURVE("BLS12_381"));

                    if ( getBool() && Pool_CurveBLSG1.Have() == true ) {
                        const auto P = Pool_CurveBLSG1.Get();
                        parameters["a_x"] = GET_OR_BIGNUM(P.g1_x);
                        parameters["a_y"] = GET_OR_BIGNUM(P.g1_y);
                    } else {
                        parameters["a_x"] = getBignum();
                        parameters["a_y"] = getBignum();
                    }

                    if ( getBool() && Pool_CurveBLSG1.Have() == true ) {
                        const auto P = Pool_CurveBLSG1.Get();
                        parameters["b_x"] = GET_OR_BIGNUM(P.g1_x);
                        parameters["b_y"] = GET_OR_BIGNUM(P.g1_y);
                    } else {
                        parameters["b_x"] = getBignum();
                        parameters["b_y"] = getBignum();
                    }

                    cryptofuzz::operation::BLS_G1_IsEq op(parameters);
                    op.Serialize(dsOut2);

                    generateECCPoint();
                }
                break;
            case    CF_OPERATION("BLS_G1_Neg"):
                {
                    parameters["modifier"] = getBuffer(PRNG() % 1000);
                    parameters["curveType"] = hint_ecc_mont(CF_ECC_CURVE("BLS12_381"));

                    if ( getBool() && Pool_CurveBLSG1.Have() == true ) {
                        const auto P = Pool_CurveBLSG1.Get();
                        parameters["a_x"] = GET_OR_BIGNUM(P.g1_x);
                        parameters["a_y"] = GET_OR_BIGNUM(P.g1_y);
                    } else {
                        parameters["a_x"] = getBignum();
                        parameters["a_y"] = getBignum();
                    }

                    cryptofuzz::operation::BLS_G1_Neg op(parameters);
                    op.Serialize(dsOut2);

                    generateECCPoint();
                }
                break;
            case    CF_OPERATION("BLS_G2_Add"):
                {
                    parameters["modifier"] = getBuffer(PRNG() % 1000);
                    parameters["curveType"] = hint_ecc_mont(CF_ECC_CURVE("BLS12_381"));

                    if ( getBool() && Pool_CurveBLSG2.Have() == true ) {
                        const auto P = Pool_CurveBLSG2.Get();
                        parameters["a_v"] = GET_OR_BIGNUM(P.g2_v);
                        parameters["a_w"] = GET_OR_BIGNUM(P.g2_w);
                        parameters["a_x"] = GET_OR_BIGNUM(P.g2_x);
                        parameters["a_y"] = GET_OR_BIGNUM(P.g2_y);
                    } else {
                        parameters["a_v"] = getBignum();
                        parameters["a_w"] = getBignum();
                        parameters["a_x"] = getBignum();
                        parameters["a_y"] = getBignum();
                    }

                    if ( getBool() && Pool_CurveBLSG2.Have() == true ) {
                        const auto P = Pool_CurveBLSG2.Get();
                        parameters["b_v"] = GET_OR_BIGNUM(P.g2_v);
                        parameters["b_w"] = GET_OR_BIGNUM(P.g2_w);
                        parameters["b_x"] = GET_OR_BIGNUM(P.g2_x);
                        parameters["b_y"] = GET_OR_BIGNUM(P.g2_y);
                    } else {
                        parameters["b_v"] = getBignum();
                        parameters["b_w"] = getBignum();
                        parameters["b_x"] = getBignum();
                        parameters["b_y"] = getBignum();
                    }

                    cryptofuzz::operation::BLS_G2_Add op(parameters);
                    op.Serialize(dsOut2);
                }
                break;
            case    CF_OPERATION("BLS_G2_Mul"):
                {
                    parameters["modifier"] = getBuffer(PRNG() % 1000);
                    parameters["curveType"] = hint_ecc_mont(CF_ECC_CURVE("BLS12_381"));

                    if ( getBool() && Pool_CurveBLSG2.Have() == true ) {
                        const auto P = Pool_CurveBLSG2.Get();
                        parameters["a_v"] = GET_OR_BIGNUM(P.g2_v);
                        parameters["a_w"] = GET_OR_BIGNUM(P.g2_w);
                        parameters["a_x"] = GET_OR_BIGNUM(P.g2_x);
                        parameters["a_y"] = GET_OR_BIGNUM(P.g2_y);
                    } else {
                        parameters["a_v"] = getBignum();
                        parameters["a_w"] = getBignum();
                        parameters["a_x"] = getBignum();
                        parameters["a_y"] = getBignum();
                    }

                    parameters["b"] = getBignum();

                    cryptofuzz::operation::BLS_G2_Mul op(parameters);
                    op.Serialize(dsOut2);
                }
                break;
            case    CF_OPERATION("BLS_G2_IsEq"):
                {
                    parameters["modifier"] = getBuffer(PRNG() % 1000);
                    parameters["curveType"] = hint_ecc_mont(CF_ECC_CURVE("BLS12_381"));

                    if ( getBool() && Pool_CurveBLSG2.Have() == true ) {
                        const auto P = Pool_CurveBLSG2.Get();
                        parameters["a_v"] = GET_OR_BIGNUM(P.g2_v);
                        parameters["a_w"] = GET_OR_BIGNUM(P.g2_w);
                        parameters["a_x"] = GET_OR_BIGNUM(P.g2_x);
                        parameters["a_y"] = GET_OR_BIGNUM(P.g2_y);
                    } else {
                        parameters["a_v"] = getBignum();
                        parameters["a_w"] = getBignum();
                        parameters["a_x"] = getBignum();
                        parameters["a_y"] = getBignum();
                    }

                    if ( getBool() && Pool_CurveBLSG2.Have() == true ) {
                        const auto P = Pool_CurveBLSG2.Get();
                        parameters["b_v"] = GET_OR_BIGNUM(P.g2_v);
                        parameters["b_w"] = GET_OR_BIGNUM(P.g2_w);
                        parameters["b_x"] = GET_OR_BIGNUM(P.g2_x);
                        parameters["b_y"] = GET_OR_BIGNUM(P.g2_y);
                    } else {
                        parameters["b_v"] = getBignum();
                        parameters["b_w"] = getBignum();
                        parameters["b_x"] = getBignum();
                        parameters["b_y"] = getBignum();
                    }

                    cryptofuzz::operation::BLS_G2_IsEq op(parameters);
                    op.Serialize(dsOut2);
                }
                break;
            case    CF_OPERATION("BLS_G2_Neg"):
                {
                    parameters["modifier"] = getBuffer(PRNG() % 1000);
                    parameters["curveType"] = hint_ecc_mont(CF_ECC_CURVE("BLS12_381"));

                    if ( getBool() && Pool_CurveBLSG2.Have() == true ) {
                        const auto P = Pool_CurveBLSG2.Get();
                        parameters["a_v"] = GET_OR_BIGNUM(P.g2_v);
                        parameters["a_w"] = GET_OR_BIGNUM(P.g2_w);
                        parameters["a_x"] = GET_OR_BIGNUM(P.g2_x);
                        parameters["a_y"] = GET_OR_BIGNUM(P.g2_y);
                    } else {
                        parameters["a_v"] = getBignum();
                        parameters["a_w"] = getBignum();
                        parameters["a_x"] = getBignum();
                        parameters["a_y"] = getBignum();
                    }

                    cryptofuzz::operation::BLS_G2_Neg op(parameters);
                    op.Serialize(dsOut2);
                }
                break;
            case    CF_OPERATION("SR25519_Verify"):
                {
                    parameters["modifier"] = getBuffer(PRNG() % 1024);

                    parameters["signature"]["pub"] = getBignum();

                    parameters["signature"]["signature"][0] = getBignum();
                    parameters["signature"]["signature"][1] = getBignum();

                    parameters["cleartext"] = cryptofuzz::util::DecToHex(getBignum(true), (PRNG() % 64) * 2);

                    cryptofuzz::operation::SR25519_Verify op(parameters);
                    op.Serialize(dsOut2);
                }
                break;
                case    CF_OPERATION("RSA_generate_key_ex"):
                {
                    uint64_t numbers[] = {3,17,65537};
                    uint64_t size = sizeof(numbers) / sizeof(numbers[0]);

                    srand(time(NULL));

                    uint64_t randomIndex = rand() % size; // create random index from 0 to size-1

                    parameters["modifier"] = getBuffer(PRNG() % 128);
                    parameters["public_exponent"] = numbers[randomIndex]; // arbitrary BIGNUM. odd number, typically 3, 17 or 65537.
                    parameters["bits"] = (PRNG() % (4096 - 1024 + 1)) + 1024; // 1024 ~ 4096size
                    cryptofuzz::operation::RSA_generate_key_ex op(parameters);
                    op.Serialize(dsOut2);
                }
                break; 
