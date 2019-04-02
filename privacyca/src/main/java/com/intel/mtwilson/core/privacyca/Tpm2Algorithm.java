/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package com.intel.mtwilson.core.privacyca;

/**
 *
 * @author dczech
 */
final class Tpm2Algorithm {

    private Tpm2Algorithm() {

    }

    public enum Hash {
        SHA1,
        SHA256
    }

    public enum Symmetric {
        AES,
        SM4
    }

    public enum SymmetricMode {
        CTR,
        OFB,
        CBC,
        CFB,
        ECB,
    }

    public enum Asymmetric {
        RSA,
        ECDSA,
        ECDH
    }
}
