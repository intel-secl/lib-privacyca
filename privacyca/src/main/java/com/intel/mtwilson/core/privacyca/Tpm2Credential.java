/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.mtwilson.core.privacyca;

/**
 *
 * @author dczech
 */
public class Tpm2Credential {
    // Size in bytes of TPM Union structures

    public final static int TPM2B_HEADER_SIZE = 8;
    public final static int TPM2B_ID_OBJECT_SIZE = 54; //Expected: 49
    public final static int TPM2B_ENCRYPTED_SECRET_SIZE = 258;

    private byte[] header; // header of credential
    private byte[] credentialBlob; // encrypted blob of credential
    private byte[] secret; // asymmetrically encrypted key, which encrypted the "credential" blob

    public Tpm2Credential(byte[] header, byte[] credentialBlob, byte[] secret) {
        this.header = header;
        this.credentialBlob = credentialBlob;
        this.secret = secret;
    }

    public byte[] getHeader() {
        return header;
    }

    public byte[] getCredential() {
        return credentialBlob;
    }

    public byte[] getSecret() {
        return secret;
    }
}
