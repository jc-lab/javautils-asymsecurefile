package kr.jclab.javautils.asymsecurefile.internal;

import kr.jclab.javautils.asymsecurefile.AsymKeyAlgorithm;
import kr.jclab.javautils.asymsecurefile.AsymmetricKeyObject;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.DigestInfo;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.security.*;

public class RSAKeyAlgorithm implements AsymKeyAlgorithm {
    private static final String CIPHER_TRANSFORMATION = "RSA/ECB/OAEPPadding";
    private static final String SIGN_ALGORITHM = "NONEWithRSA";

    @Override
    public KeyPair generateKeyPair(AlgorithmIdentifier algorithmIdentifier, int keySize, Provider securityProvider) throws NoSuchAlgorithmException {
        KeyPairGenerator kpg;
        if(securityProvider != null)
            kpg = KeyPairGenerator.getInstance("RSA", securityProvider);
        else
            kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(keySize);
        return kpg.generateKeyPair();
    }

    @Override
    public Cipher createEncipher(AsymmetricKeyObject keyObject) throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException {
        Cipher cipher;
        if(keyObject.getSecurityProvider() != null)
            cipher = Cipher.getInstance(CIPHER_TRANSFORMATION, keyObject.getSecurityProvider());
        else
            cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, keyObject.getKey());
        return cipher;
    }

    @Override
    public Cipher createDecipher(AsymmetricKeyObject keyObject) throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException {
        Cipher cipher;
        if(keyObject.getSecurityProvider() != null)
            cipher = Cipher.getInstance(CIPHER_TRANSFORMATION, keyObject.getSecurityProvider());
        else
            cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
        cipher.init(Cipher.DECRYPT_MODE, keyObject.getKey());
        return cipher;
    }

    @Override
    public Signature createSigner(AsymmetricKeyObject keyObject) throws NoSuchAlgorithmException, InvalidKeyException {
        Signature signature;
        if(keyObject.getSecurityProvider() != null)
            signature = Signature.getInstance(SIGN_ALGORITHM, keyObject.getSecurityProvider());
        else
            signature = Signature.getInstance(SIGN_ALGORITHM);
        signature.initSign((PrivateKey)keyObject.getKey());
        return signature;
    }

    @Override
    public Signature createVerifier(AsymmetricKeyObject keyObject) throws NoSuchAlgorithmException, InvalidKeyException {
        Signature signature;
        if(keyObject.getSecurityProvider() != null)
            signature = Signature.getInstance(SIGN_ALGORITHM, keyObject.getSecurityProvider());
        else
            signature = Signature.getInstance(SIGN_ALGORITHM);
        signature.initVerify((PublicKey) keyObject.getKey());
        return signature;
    }

    @Override
    public KeyAgreement createKeyAgreement(AsymmetricKeyObject keyObject) throws NoSuchAlgorithmException, InvalidKeyException {
        throw new RuntimeException("not supported operation");
    }

    @Override
    public byte[] sign(AsymmetricKeyObject keyObject, AlgorithmIdentifier digestAlgorithmIdentifier, byte[] hash) throws IOException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        DigestInfo digestInfo = new DigestInfo(digestAlgorithmIdentifier, hash);
        Signature s = createSigner(keyObject);
        s.update(digestInfo.getEncoded());
        return s.sign();
    }

    @Override
    public boolean verify(AsymmetricKeyObject keyObject, AlgorithmIdentifier digestAlgorithmIdentifier, byte[] hash, byte[] signature) throws IOException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        DigestInfo digestInfo = new DigestInfo(digestAlgorithmIdentifier, hash);
        Signature s = createVerifier(keyObject);
        s.update(digestInfo.getEncoded());
        return s.verify(signature);
    }
}
