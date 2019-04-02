/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.mtwilson.core.privacyca;

import gov.niarl.his.privacyca.TpmUtils;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;

/**
 *
 * @author dczech
 */
class Utils {

    public static RSAPublicKey makeRSAPublicKey(byte[] modulus) throws InvalidKeySpecException, NoSuchAlgorithmException {
        BigInteger modI = new BigInteger(1, modulus);
        BigInteger expI = BigInteger.valueOf(65537);
        RSAPublicKeySpec newKeySpec = new RSAPublicKeySpec(modI, expI);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        RSAPublicKey newKey = (RSAPublicKey) keyFactory.generatePublic(newKeySpec);
        return newKey;
    }

    public static byte[] createEkBlob(byte[] key, byte[] aikDigest) {
        try {
            /* it seems Windows uses TPM_EK_BLOB for TPM_ActivateIdentity. so we have to form that for Windows
            typedef struct tdTPM_EK_BLOB{
            TPM_STRUCTURE_TAG tag;
            TPM_EK_TYPE ekType;
            UINT32 blobSize;
            [size_is(blobSize)] BYTE* blob;
            } TPM_EK_BLOB;
            typedef struct tdTPM_EK_BLOB_ACTIVATE{
            TPM_STRUCTURE_TAG tag;
            TPM_SYMMETRIC_KEY sessionKey;
            TPM_DIGEST idDigest;
            TPM_PCR_INFO_SHORT pcrInfo;
            } TPM_EK_BLOB_ACTIVATE;
             */
            int cbActivation = 2
                    + //TPM_STRUCTURE_TAG tag = TPM_TAG_EK_BLOB
                    2
                    + //TPM_EK_TYPE ekType = TPM_EK_TYPE_ACTIVATE
                    4
                    + //UINT32 blobSize = cbActivation - (2 * sizeof(UINT16) + sizeof(UINT32))
                    2
                    + //TPM_STRUCTURE_TAG tag = TPM_TAG_EK_BLOB_ACTIVATE
                    4
                    + //TPM_ALGORITHM_ID algId = TPM_ALG_XOR
                    2
                    + //TPM_ENC_SCHEME encScheme = TPM_ES_NONE
                    2
                    + //UINT16 size
                    key.length
                    + aikDigest.length
                    + //cbAikDigest +
                    2
                    + // UINT16 sizeOfSelect = 3
                    3
                    + // PcrSelect
                    1
                    + //TPM_LOCALITY_SELECTION localityAtRelease = TPM_LOC_ZERO
                    20; //TPM_COMPOSITE_HASH digestAtRelease = 0
            byte[] activationBlob = new byte[cbActivation];
            short sVal;
            int intVal; // parameters to contrusct the activationBlob
            int index = 0;
            sVal = 0x000c; //TPM_STRUCTURE_TAG
            System.arraycopy(TpmUtils.shortToByteArray(sVal), 0, activationBlob, index, 2);
            index = index + 2;
            sVal = 0x0001; //TPM_EK_TYPE
            System.arraycopy(TpmUtils.shortToByteArray(sVal), 0, activationBlob, index, 2);
            index = index + 2;
            intVal = cbActivation - 8; //blobSize
            System.arraycopy(TpmUtils.intToByteArray(intVal), 0, activationBlob, index, 4);
            index = index + 4;
            sVal = 0x002b; // TPM_TAG_EK_BLOB_ACTIVATE
            System.arraycopy(TpmUtils.shortToByteArray(sVal), 0, activationBlob, index, 2);
            index = index + 2;
            //intVal = TpmKeyParams.TPM_ALG_AES; //not TPM_ALG_XOR
            intVal = 0x0000000a; //not TPM_ALG_XOR
            System.arraycopy(TpmUtils.intToByteArray(intVal), 0, activationBlob, index, 4);
            index = index + 4;
            //sVal = TpmKeyParams.TPM_ES_SYM_CBC_PKCS5PAD; //TPM_ES_NONE
            sVal = 0x0001; //TPM_ES_NONE
            System.arraycopy(TpmUtils.shortToByteArray(sVal), 0, activationBlob, index, 2);
            index = index + 2;
            sVal = (short) key.length;
            System.arraycopy(TpmUtils.shortToByteArray(sVal), 0, activationBlob, index, 2);
            index = index + 2;
            System.arraycopy(key, 0, activationBlob, index, key.length);
            index = index + key.length;
            System.arraycopy(aikDigest, 0, activationBlob, index, aikDigest.length);
            index = index + aikDigest.length;
            sVal = 0x0003; // UINT16 sizeOfSelect = 3
            System.arraycopy(TpmUtils.shortToByteArray(sVal), 0, activationBlob, index, 2);
            index = index + 2;
            index = index + 3; // 3 bytes of 0 PcrSelect
            byte[] loczero = new byte[1];
            loczero[0] = (byte) 0x01; //TPM_LOC_ZERO
            System.arraycopy(loczero, 0, activationBlob, index, 1);
            //#5834: Variable 'index' was never read after being assigned.
            //index = index + 1;
            // the digest is 0, so no need to copy
            //index = index + 20;
            return activationBlob;
        } catch (TpmUtils.TpmUnsignedConversionException ex) {
            throw new RuntimeException();
        }
    }
}
