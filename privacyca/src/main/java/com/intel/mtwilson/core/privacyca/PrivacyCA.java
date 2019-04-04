/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.mtwilson.core.privacyca;

import com.intel.mtwilson.core.common.tpm.model.IdentityRequest;
import com.intel.mtwilson.core.common.tpm.model.IdentityProofRequest;
import gov.niarl.his.privacyca.PrivacyCaException;
import gov.niarl.his.privacyca.TpmIdentityProof;
import gov.niarl.his.privacyca.TpmIdentityRequest;
import gov.niarl.his.privacyca.TpmKeyParams;
import gov.niarl.his.privacyca.TpmPubKey;
import gov.niarl.his.privacyca.TpmSymmetricKey;
import gov.niarl.his.privacyca.TpmUtils;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Calendar;
import java.util.Date;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/**
 *
 * @author dczech
 */
public class PrivacyCA {

    /**
     * <p>Process an IdentityRequest Object returned from a TPM.
     * This function will encrypt an blob of data using the public portion of a key found inside the IdentityRequest object.
     * If a TPM can decrypt the blob of data, that serves as a proof of ownership over the private portion of that key.
     * </p>
     * @param request an IdentityRequest object returned from TpmProvider.collateIdentityRequest()
     * @param caPrivKey private key of the PrivacyCA
     * @param caPubKey public key of the PrivacyCA
     * @param ekPub public portion of the Tpms Endorsement Key
     * @param dataBlob arbitrary data the PrivacyCA wishes to encrypt. Can be a random challenge or an AIKCert, etc.
     * @return IdentityProofRequest java model object.
     * @throws PCAException This method throws PCAException
     */
    public static IdentityProofRequest processIdentityRequest(IdentityRequest request, RSAPrivateKey caPrivKey, RSAPublicKey caPubKey, RSAPublicKey ekPub, byte[] dataBlob) throws PCAException {
        switch (request.getTpmVersion()) {
            case "1.2":
                return processV12(request, caPrivKey, caPubKey, ekPub, dataBlob);
            case "2.0":
                return processV20(request, ekPub, dataBlob);
            default:
                throw new IllegalArgumentException("Unknown TPM Version");
        }
    }
    
    /**
     * <p>
     * Helper method to quickly generate an AIK Certificate using the PrivacyCA's signing key and certificate.
     * It is not recommended to use this in production, as you should be generating certificates on your own with more granularity.
     * </p>
     * @param aik public key of the AIK
     * @param sanLabel The sanLabel
     * @param caPrivKey private key of the PrivacyCA
     * @param caCert The CA certificate
     * @param validityDays Certificate validity days
     * @return X509Certificate AIK certificate in x509 format.
     * @throws CertificateException This method throws CertificateException
     * @throws OperatorCreationException This method throws OperatorCreationException
     */
    public static X509Certificate makeAikCertificate(PublicKey aik, String sanLabel, PrivateKey caPrivKey, X509Certificate caCert, int validityDays) throws CertificateException, OperatorCreationException, CertIOException {
        Calendar calendar = Calendar.getInstance();
        Date now = calendar.getTime();
        calendar.add(Calendar.DATE, validityDays);
        Date expiry = calendar.getTime();
        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(caCert,
                BigInteger.valueOf(System.currentTimeMillis()),
                now, 
                expiry, 
                new X500Principal(""),
                aik);
        certBuilder.addExtension(X509Extension.subjectAlternativeName, true, new GeneralNames(new GeneralName(GeneralName.rfc822Name, sanLabel)));
        X509CertificateHolder holder = certBuilder.build(new JcaContentSignerBuilder("SHA256withRSA").setProvider("BC").build(caPrivKey));
        return new JcaX509CertificateConverter().setProvider("BC").getCertificate(holder);
    }
    
    /**
     * <p>
     * Helper method to quickly generate an Endorsement Certificate using the PrivacyCA's signing key and certificate.
     * It is not recommended to use this in production, as you should be generating certificates on your own with more granularity.
     * @param endorsementKey public portion of the Tpms Endorsement Key
     * @param caPrivKey private key of the PrivacyCA
     * @param caCert The CA certificate
     * @param validityDays Certificate validity days
     * @return X509Certificate Endorsement certificate in x509 format
     * @throws CertificateException This method throws CertificateException
     * @throws OperatorCreationException This method throws OperatorCreationException
     */
    public static X509Certificate makeEndorsementCertificate(PublicKey endorsementKey, PrivateKey caPrivKey, X509Certificate caCert, int validityDays) throws CertificateException, OperatorCreationException, CertIOException {
        return makeAikCertificate(endorsementKey, "TPM EK Certificate", caPrivKey, caCert, validityDays);
    }

    private static IdentityProofRequest processV20(IdentityRequest request, RSAPublicKey pubEk, byte[] dataBlob) throws PCAException {
        try {
            byte[] key = TpmUtils.createRandomBytes(16);
            byte[] iv = TpmUtils.createRandomBytes(16);
            byte[] encryptedBlob = TpmUtils.concat(iv, TpmUtils.tcgSymEncrypt(dataBlob, key, iv));
            Tpm2Credential credential = Tpm2.makeCredential(pubEk, Tpm2Algorithm.Symmetric.AES, 128, Tpm2Algorithm.Hash.SHA256, key, request.getAikName());
            IdentityProofRequest proofReq = new IdentityProofRequest();
            proofReq.setCredential(credential.getCredential());
            proofReq.setSecret(credential.getSecret());
            TpmPubKey tpk = new TpmPubKey(Utils.makeRSAPublicKey(request.getAikModulus()), 0x1, 0x4);
            byte[] ekBlob = Utils.createEkBlob(key, TpmUtils.sha256hash(tpk.toByteArray()));
            proofReq.setEkBlob(TpmUtils.tcgAsymEncrypt256(ekBlob, pubEk));
            TpmKeyParams keyParms = new TpmKeyParams();
            keyParms.setAlgorithmId(TpmKeyParams.TPM_ALG_AES);
            keyParms.setEncScheme(TpmKeyParams.TPM_ES_NONE);
            keyParms.setSigScheme((short) 0);
            keyParms.setSubParams(null);
            keyParms.setTrouSerSmode(true);
            proofReq.setSymBlob(TpmUtils.concat(TpmUtils.concat(TpmUtils.intToByteArray(encryptedBlob.length), keyParms.toByteArray()), encryptedBlob));
            return proofReq;
        } catch (TpmUtils.TpmUnsignedConversionException | InvalidKeySpecException | NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException | IOException ex) {
            throw new PCAException(ex);
        } 
    }

    private static IdentityProofRequest processV12(IdentityRequest request, RSAPrivateKey caPrivKey, RSAPublicKey caPubKey, RSAPublicKey ekPub, byte[] dataBlob) throws PCAException {
        try {
            TpmIdentityRequest idReq = new TpmIdentityRequest(request.getIdentityRequestBlob());
            TpmIdentityProof idProof = idReq.decrypt(caPrivKey);
            if (!idProof.checkValidity(caPubKey)) {
                throw new RuntimeException("Could not validate TpmIdentityProof with provided caPubKey");
            }
            byte[] key = TpmUtils.createRandomBytes(16);
            byte[] iv = TpmUtils.createRandomBytes(16);
            byte[] encryptedBlob = TpmUtils.concat(iv, TpmUtils.tcgSymEncrypt(dataBlob, key, iv));
            byte[] credSize = TpmUtils.intToByteArray(encryptedBlob.length);

            TpmSymmetricKey symKey = new TpmSymmetricKey();
            symKey.setKeyBlob(key);
            symKey.setAlgorithmId(TpmKeyParams.TPM_ALG_AES);
            symKey.setEncScheme(TpmKeyParams.TPM_ES_SYM_CBC_PKCS5PAD);
            TpmKeyParams keyParms = new TpmKeyParams();
            keyParms.setAlgorithmId(TpmKeyParams.TPM_ALG_AES);
            keyParms.setEncScheme(TpmKeyParams.TPM_ES_NONE);
            keyParms.setSigScheme((short) 0);
            keyParms.setSubParams(null);
            keyParms.setTrouSerSmode(true);

            TpmPubKey aik = idProof.getAik();
            byte[] asymBlob = TpmUtils.tcgAsymEncrypt(TpmUtils.concat(symKey.toByteArray(), TpmUtils.sha1hash(aik.toByteArray())), ekPub);
            byte[] symBlob = TpmUtils.concat(TpmUtils.concat(credSize, keyParms.toByteArray()), encryptedBlob);
            IdentityProofRequest proofReq = new IdentityProofRequest();
            proofReq.setAsymBlob(asymBlob);
            proofReq.setSymBlob(symBlob);
            byte[] ekBlob = Utils.createEkBlob(key, TpmUtils.sha1hash(aik.toByteArray()));
            proofReq.setEkBlob(TpmUtils.tcgAsymEncrypt(ekBlob, ekPub));

            return proofReq;
        } catch (TpmUtils.TpmUnsignedConversionException | TpmUtils.TpmBytestreamResouceException | InvalidKeyException | PrivacyCaException | IllegalBlockSizeException | InvalidAlgorithmParameterException | NoSuchAlgorithmException | BadPaddingException | NoSuchPaddingException | IOException | InvalidKeySpecException | SignatureException ex) {
            throw new PCAException(ex);
        }
    }
}
