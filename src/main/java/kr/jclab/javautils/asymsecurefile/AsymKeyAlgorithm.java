package kr.jclab.javautils.asymsecurefile;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.security.*;

public interface AsymKeyAlgorithm {
    KeyPair generateKeyPair(AlgorithmIdentifier algorithmIdentifier, int keySize, Provider securityProvider) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException;
    Cipher createEncipher(AsymmetricKeyObject keyObject) throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException;
    Cipher createDecipher(AsymmetricKeyObject keyObject) throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException;
    Signature createSigner(AsymmetricKeyObject keyObject) throws NoSuchAlgorithmException, InvalidKeyException;
    Signature createVerifier(AsymmetricKeyObject keyObject) throws NoSuchAlgorithmException, InvalidKeyException;
    byte[] sign(AsymmetricKeyObject keyObject, AlgorithmIdentifier digestAlgorithmIdentifier, byte[] hash) throws IOException, NoSuchAlgorithmException, InvalidKeyException, IOException, SignatureException, SignatureException;
    boolean verify(AsymmetricKeyObject keyObject, AlgorithmIdentifier digestAlgorithmIdentifier, byte[] hash, byte[] signature) throws IOException, NoSuchAlgorithmException, InvalidKeyException, SignatureException;
    KeyAgreement createKeyAgreement(AsymmetricKeyObject keyObject) throws NoSuchAlgorithmException, InvalidKeyException;
}
