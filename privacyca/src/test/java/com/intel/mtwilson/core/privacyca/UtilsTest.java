/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.mtwilson.core.privacyca;

import gov.niarl.his.privacyca.TpmUtils;
import java.security.NoSuchAlgorithmException;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author dczech
 */
public class UtilsTest {
    
    public UtilsTest() {
    }
    
    @BeforeClass
    public static void setUpClass() {
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

    /**
     * Test of createEkBlob method, of class Utils.
     */
    @Test
    public void testCreateEkBlob() throws NoSuchAlgorithmException, NoSuchAlgorithmException {
        System.out.println("createEkBlob");
        byte[] key = new byte[]{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5};
        byte[] aikDigest = TpmUtils.sha1hash(new byte[]{0, 1, 2, 3, 5, 6});
        byte[] result = Utils.createEkBlob(key, aikDigest);
        assertTrue(result.length > 0);
    }  
}
