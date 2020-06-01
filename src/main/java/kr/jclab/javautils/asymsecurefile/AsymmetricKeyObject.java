package kr.jclab.javautils.asymsecurefile;

import kr.jclab.javautils.asymsecurefile.internal.AsymmetricAlgorithmType;
import kr.jclab.javautils.asymsecurefile.internal.ECKeyAlgorithm;
import kr.jclab.javautils.asymsecurefile.internal.RSAKeyAlgorithm;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;

import javax.crypto.*;
import java.io.IOException;
import java.security.*;
import java.security.interfaces.ECKey;
import java.security.interfaces.RSAKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

public class AsymmetricKeyObject {
    private final PrivateKey privateKey;
    private final PublicKey publicKey;
    private final Provider securityProvider;
    private final AsymmetricAlgorithmType algorithmType;
    private final AlgorithmIdentifier algorithmIdentifier;
    private final int keySize;

    private final boolean signable;
    private final boolean verifyable;
    private final boolean keyAgreementable;
    private final boolean publicEncryptable;
    private final boolean privateDecryptable;

    private final AsymKeyAlgorithm keyAlgorithm;

    private AsymmetricKeyObject(Key key, Provider securityProvider, AsymmetricAlgorithmType algorithmType, AlgorithmIdentifier algorithmIdentifier, AsymKeyAlgorithm keyAlgorithm, int keySize, boolean signable, boolean verifyable, boolean keyAgreementable, boolean publicEncryptable, boolean privateDecryptable) {
        if(key instanceof PrivateKey) {
            this.privateKey = (PrivateKey)key;
            this.publicKey = null;
        }else{
            this.publicKey = (PublicKey)key;
            this.privateKey = null;
        }
        this.securityProvider = securityProvider;
        this.algorithmType = algorithmType;
        this.algorithmIdentifier = algorithmIdentifier;
        this.keyAlgorithm = keyAlgorithm;
        this.keySize = keySize;
        this.signable = signable;
        this.verifyable = verifyable;
        this.keyAgreementable = keyAgreementable;
        this.publicEncryptable = publicEncryptable;
        this.privateDecryptable = privateDecryptable;
    }

    private AsymmetricKeyObject(KeyPair keyPair, Provider securityProvider, AsymmetricAlgorithmType algorithmType, AlgorithmIdentifier algorithmIdentifier, AsymKeyAlgorithm keyAlgorithm, int keySize, boolean signable, boolean verifyable, boolean keyAgreementable, boolean publicEncryptable, boolean privateDecryptable) {
        this.privateKey = keyPair.getPrivate();
        this.publicKey = keyPair.getPublic();
        this.securityProvider = securityProvider;
        this.algorithmType = algorithmType;
        this.algorithmIdentifier = algorithmIdentifier;
        this.keyAlgorithm = keyAlgorithm;
        this.keySize = keySize;
        this.signable = signable;
        this.verifyable = verifyable;
        this.keyAgreementable = keyAgreementable;
        this.publicEncryptable = publicEncryptable;
        this.privateDecryptable = privateDecryptable;
    }

    public static AsymmetricKeyObject fromPublicKey(SubjectPublicKeyInfo publicKeyInfo, Provider securityProvider) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        AsymmetricAlgorithmType algorithmType;
        int keySize = 0;
        PublicKey key;
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyInfo.getEncoded("X509"));
        ASN1ObjectIdentifier keySpecOid = (publicKeyInfo.getAlgorithm().getParameters() instanceof ASN1ObjectIdentifier) ? ((ASN1ObjectIdentifier)publicKeyInfo.getAlgorithm().getParameters()) : null;
        if(keySpecOid == null) {
            keySpecOid = publicKeyInfo.getAlgorithm().getAlgorithm();
        }
        AlgorithmIdentifier algorithmIdentifier = publicKeyInfo.getAlgorithm();

        if(X9ObjectIdentifiers.id_ecPublicKey.equals(algorithmIdentifier.getAlgorithm())) {
            KeyFactory kf = KeyFactory.getInstance("EC", securityProvider);
            key = kf.generatePublic(keySpec);
        }else if(PKCSObjectIdentifiers.rsaEncryption.equals(algorithmIdentifier.getAlgorithm())) {
            KeyFactory kf = KeyFactory.getInstance("RSA", securityProvider);
            key = kf.generatePublic(keySpec);
        }else{
            throw new NotSupportAlgorithmException("Not supported Key");
        }

        if(key instanceof ECKey) {
            algorithmType = AsymmetricAlgorithmType.ec;
            keySize = ((ECKey)key).getParams().getCurve().getField().getFieldSize();
            return new AsymmetricKeyObject(
                    key,
                    securityProvider,
                    algorithmType,
                    algorithmIdentifier,
                    new ECKeyAlgorithm(),
                    keySize,
                    (key instanceof PrivateKey),
                    (key instanceof PublicKey),
                    true,
                    false,
                    false
            );
        }else if(key instanceof RSAKey) {
            algorithmType = AsymmetricAlgorithmType.rsa;
            keySize = ((RSAKey)key).getModulus().bitLength();
            return new AsymmetricKeyObject(
                    key,
                    securityProvider,
                    algorithmType,
                    algorithmIdentifier,
                    new RSAKeyAlgorithm(),
                    keySize,
                    (key instanceof PrivateKey),
                    (key instanceof PublicKey),
                    false,
                    (key instanceof PrivateKey),
                    (key instanceof PublicKey)
            );
        }else{
            throw new NotSupportAlgorithmException("Unknown Key Type");
        }
    }

    public static AsymmetricKeyObject fromKey(Key key, Provider securityProvider) throws NotSupportAlgorithmException {
        AlgorithmIdentifier algorithmIdentifier = null;
        AsymmetricAlgorithmType algorithmType = null;

        byte[] encoded = key.getEncoded();
        ASN1ObjectIdentifier keySpecOid = null;
        int keySize = 0;
        if(key instanceof PrivateKey) {
            // Private Key
            PrivateKeyInfo privateKeyInfo = PrivateKeyInfo.getInstance(encoded);
            keySpecOid = (privateKeyInfo.getPrivateKeyAlgorithm().getParameters() instanceof ASN1ObjectIdentifier) ? ((ASN1ObjectIdentifier)privateKeyInfo.getPrivateKeyAlgorithm().getParameters()) : null;
            if(keySpecOid == null) {
                keySpecOid = privateKeyInfo.getPrivateKeyAlgorithm().getAlgorithm();
            }
            algorithmIdentifier = privateKeyInfo.getPrivateKeyAlgorithm();
        }else if(key instanceof PublicKey) {
            SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfo.getInstance(encoded);
            keySpecOid = (publicKeyInfo.getAlgorithm().getParameters() instanceof ASN1ObjectIdentifier) ? ((ASN1ObjectIdentifier)publicKeyInfo.getAlgorithm().getParameters()) : null;
            if(keySpecOid == null) {
                keySpecOid = publicKeyInfo.getAlgorithm().getAlgorithm();
            }
            algorithmIdentifier = publicKeyInfo.getAlgorithm();
        }else{
            throw new NotSupportAlgorithmException("Unknown Key Type");
        }

        if(key instanceof ECKey) {
            algorithmType = AsymmetricAlgorithmType.ec;
            keySize = ((ECKey)key).getParams().getCurve().getField().getFieldSize();
            return new AsymmetricKeyObject(
                    key,
                    securityProvider,
                    algorithmType,
                    algorithmIdentifier,
                    new ECKeyAlgorithm(),
                    keySize,
                    (key instanceof PrivateKey),
                    (key instanceof PublicKey),
                    true,
                    false,
                    false
            );
        }else if(key instanceof RSAKey) {
            algorithmType = AsymmetricAlgorithmType.rsa;
            keySize = ((RSAKey)key).getModulus().bitLength();
            return new AsymmetricKeyObject(
                    key,
                    securityProvider,
                    algorithmType,
                    algorithmIdentifier,
                    new RSAKeyAlgorithm(),
                    keySize,
                    (key instanceof PrivateKey),
                    (key instanceof PublicKey),
                    false,
                    (key instanceof PublicKey),
                    (key instanceof PrivateKey)
            );
        }else{
            throw new NotSupportAlgorithmException("Unknown Key Type");
        }
    }

    public static AsymmetricKeyObject fromKey(KeyPair keyPair, Provider securityProvider) throws NotSupportAlgorithmException {
        AsymmetricAlgorithmType algorithmType = null;
        int keySize = 0;

        SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded());
        ASN1ObjectIdentifier keySpecOid = (publicKeyInfo.getAlgorithm().getParameters() instanceof ASN1ObjectIdentifier) ? ((ASN1ObjectIdentifier)publicKeyInfo.getAlgorithm().getParameters()) : null;
        if(keySpecOid == null) {
            keySpecOid = publicKeyInfo.getAlgorithm().getAlgorithm();
        }
        AlgorithmIdentifier algorithmIdentifier = publicKeyInfo.getAlgorithm();

        if("ec".equalsIgnoreCase(keyPair.getPrivate().getAlgorithm())) {
            algorithmType = AsymmetricAlgorithmType.ec;
            ECKey ecPublicKey = (ECKey)keyPair.getPublic();
            keySize = ecPublicKey.getParams().getCurve().getField().getFieldSize();
            return new AsymmetricKeyObject(
                    keyPair,
                    securityProvider,
                    algorithmType,
                    algorithmIdentifier,
                    new ECKeyAlgorithm(),
                    keySize,
                    true,
                    true,
                    true,
                    false,
                    false
            );
        }else if("rsa".equalsIgnoreCase(keyPair.getPrivate().getAlgorithm())) {
            algorithmType = AsymmetricAlgorithmType.rsa;
            RSAKey rsaPublicKey = (RSAKey)keyPair.getPublic();
            keySize = rsaPublicKey.getModulus().bitLength();
            return new AsymmetricKeyObject(
                    keyPair,
                    securityProvider,
                    algorithmType,
                    algorithmIdentifier,
                    new RSAKeyAlgorithm(),
                    keySize,
                    true,
                    true,
                    false,
                    true,
                    true
            );
        }else{
            throw new NotSupportAlgorithmException("Unknown Key Type");
        }
    }

//    public Key getKey() {
//        if (this.privateKey != null) {
//            return this.privateKey;
//        }
//        return this.publicKey;
//    }

    public Key getPrivateKey() {
        return privateKey;
    }

    public Key getPublicKey() {
        return publicKey;
    }

    public Provider getSecurityProvider() {
        return securityProvider;
    }

    public AsymmetricAlgorithmType getAlgorithmType() {
        return algorithmType;
    }

    public AlgorithmIdentifier getAlgorithmIdentifier() {
        return algorithmIdentifier;
    }

    public int getKeySize() {
        return keySize;
    }

    public boolean isSignable() {
        return signable;
    }

    public boolean isVerifyable() {
        return verifyable;
    }

    public boolean isKeyAgreementable() {
        return keyAgreementable;
    }

    public boolean isPublicEncryptable() {
        return publicEncryptable;
    }

    public boolean isPrivateDecryptable() {
        return privateDecryptable;
    }

    public KeyPair generateKeyPair() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException {
        return this.keyAlgorithm.generateKeyPair(this.algorithmIdentifier, this.keySize, this.securityProvider);
    }

    public byte[] publicEncrypt(byte[] plaintext) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = this.keyAlgorithm.createEncipher(this);
        return cipher.doFinal(plaintext);
    }

    public byte[] privateDecrypt(byte[] ciphertext) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = this.keyAlgorithm.createDecipher(this);
        return cipher.doFinal(ciphertext);
    }

    public KeyAgreement createKeyAgreement() throws InvalidKeyException, NoSuchAlgorithmException {
        return this.keyAlgorithm.createKeyAgreement(this);
    }

    public Signature createSigner() throws InvalidKeyException, NoSuchAlgorithmException {
        return this.keyAlgorithm.createSigner(this);
    }

    public Signature createVerifier() throws InvalidKeyException, NoSuchAlgorithmException {
        return this.keyAlgorithm.createVerifier(this);
    }

    public byte[] sign(AlgorithmIdentifier digestAlgorithmIdentifier, byte[] hash) throws SignatureException, NoSuchAlgorithmException, InvalidKeyException, IOException {
        return this.keyAlgorithm.sign(this, digestAlgorithmIdentifier, hash);
    }

    public boolean verify(AlgorithmIdentifier digestAlgorithmIdentifier, byte[] hash, byte[] signature) throws SignatureException, NoSuchAlgorithmException, InvalidKeyException, IOException {
        return this.keyAlgorithm.verify(this, digestAlgorithmIdentifier, hash, signature);
    }
}
