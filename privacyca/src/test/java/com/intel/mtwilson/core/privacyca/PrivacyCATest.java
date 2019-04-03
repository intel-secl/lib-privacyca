/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.mtwilson.core.privacyca;

import com.intel.mtwilson.core.common.tpm.model.IdentityProofRequest;
import com.intel.mtwilson.core.common.tpm.model.IdentityRequest;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import javax.crypto.ShortBufferException;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;
import org.junit.Ignore;

/**
 *
 * @author dczech
 */
public class PrivacyCATest {
    
    public PrivacyCATest() {
    }
    
    static byte[] name; 
    @BeforeClass
    public static void setUpClass() {
        name = "HIS_Identity_Key".getBytes();
    }
    
    @AfterClass
    public static void tearDownClass() {
    }
    
    @Before
    public void setUp() {
    }
    
    @After
    public void tearDown() {
    }

    private KeyPair generateKey() throws NoSuchAlgorithmException {
        KeyPairGenerator keygen = KeyPairGenerator.getInstance("RSA");
        keygen.initialize(2048);
        
        return keygen.genKeyPair();
    }
    
    /**
     * Test of processIdentityRequest method, of class PrivacyCA.
     */
    @Ignore
    @Test
    public void testProcessIdentityRequest12() throws NoSuchAlgorithmException, PCAException, ShortBufferException {
        System.out.println("processIdentityRequest");
        IdentityRequest request = new IdentityRequest("1.2", null, null, null, name);
        KeyPair ca = generateKey();
        RSAPrivateKey caPrivKey = (RSAPrivateKey) ca.getPrivate();
        RSAPublicKey caPubKey = (RSAPublicKey) ca.getPublic();
        KeyPair mockEk = generateKey();
        RSAPublicKey ekPub = (RSAPublicKey) mockEk.getPublic();
        byte[] dataBlob = null;
        IdentityProofRequest expResult = null;
        IdentityProofRequest result = PrivacyCA.processIdentityRequest(request, caPrivKey, caPubKey, ekPub, dataBlob);
        assertEquals(expResult, result);
        // TODO review the generated test code and remove the default call to fail.
        fail("The test case is a prototype.");
    }
    
    @Ignore
    @Test
    public void testProcessIdentityRequest20() {
        
    }
}
