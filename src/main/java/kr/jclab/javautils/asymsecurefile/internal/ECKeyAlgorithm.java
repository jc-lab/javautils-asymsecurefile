package kr.jclab.javautils.asymsecurefile.internal;

import kr.jclab.javautils.asymsecurefile.AsymKeyAlgorithm;
import kr.jclab.javautils.asymsecurefile.AsymmetricKeyObject;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.jce.spec.ECParameterSpec;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import java.io.IOException;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;

public class ECKeyAlgorithm implements AsymKeyAlgorithm {
    private static final String SIGN_ALGORITHM = "NONEWithECDSA";

    @Override
    public KeyPair generateKeyPair(AlgorithmIdentifier algorithmIdentifier, int keySize, Provider securityProvider) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        KeyPairGenerator kpg;
        if(securityProvider != null)
            kpg = KeyPairGenerator.getInstance("EC", securityProvider);
        else
            kpg = KeyPairGenerator.getInstance("EC");
        AlgorithmParameterSpec parameters;
        if (algorithmIdentifier.getParameters() instanceof ASN1ObjectIdentifier) {
            ASN1ObjectIdentifier oid = ((ASN1ObjectIdentifier) algorithmIdentifier.getParameters());
            parameters = new ECGenParameterSpec(oid.getId());
        }else{
            X9ECParameters ecP = X9ECParameters.getInstance(algorithmIdentifier.getParameters());
            parameters = new ECParameterSpec(ecP.getCurve(), ecP.getG(), ecP.getN(), ecP.getH(), ecP.getSeed());
        }
        kpg.initialize(parameters);
        return kpg.generateKeyPair();
    }

    @Override
    public Cipher createEncipher(AsymmetricKeyObject keyObject) throws NoSuchAlgorithmException, InvalidKeyException {
        throw new RuntimeException("not supported operation");
    }

    @Override
    public Cipher createDecipher(AsymmetricKeyObject keyObject) throws NoSuchAlgorithmException, InvalidKeyException {
        throw new RuntimeException("not supported operation");
    }

    @Override
    public Signature createSigner(AsymmetricKeyObject keyObject) throws NoSuchAlgorithmException, InvalidKeyException {
        Signature signature;
        if(keyObject.getSecurityProvider() != null)
            signature = Signature.getInstance(SIGN_ALGORITHM, keyObject.getSecurityProvider());
        else
            signature = Signature.getInstance(SIGN_ALGORITHM);
        signature.initSign((PrivateKey)keyObject.getPrivateKey());
        return signature;
    }

    @Override
    public Signature createVerifier(AsymmetricKeyObject keyObject) throws NoSuchAlgorithmException, InvalidKeyException {
        Signature signature;
        if(keyObject.getSecurityProvider() != null)
            signature = Signature.getInstance(SIGN_ALGORITHM, keyObject.getSecurityProvider());
        else
            signature = Signature.getInstance(SIGN_ALGORITHM);
        signature.initVerify((PublicKey) keyObject.getPublicKey());
        return signature;
    }

    @Override
    public KeyAgreement createKeyAgreement(AsymmetricKeyObject keyObject) throws NoSuchAlgorithmException, InvalidKeyException {
        KeyAgreement keyAgreement;
        if(keyObject.getSecurityProvider() != null)
            keyAgreement = KeyAgreement.getInstance("ECDH", keyObject.getSecurityProvider());
        else
            keyAgreement = KeyAgreement.getInstance("ECDH");
        keyAgreement.init(keyObject.getPrivateKey());
        return keyAgreement;
    }

    @Override
    public byte[] sign(AsymmetricKeyObject keyObject, AlgorithmIdentifier digestAlgorithmIdentifier, byte[] hash) throws IOException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature s = createSigner(keyObject);
        s.update(hash);
        return s.sign();
    }

    @Override
    public boolean verify(AsymmetricKeyObject keyObject, AlgorithmIdentifier digestAlgorithmIdentifier, byte[] hash, byte[] signature) throws IOException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature s = createVerifier(keyObject);
        s.update(hash);
        return s.verify(signature);
    }
}
