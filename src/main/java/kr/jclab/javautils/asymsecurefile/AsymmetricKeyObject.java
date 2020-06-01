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
    private final Key key;
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
        this.key = key;
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
        if("PKCS#8".equalsIgnoreCase(key.getFormat())) {
            // Private Key
            PrivateKeyInfo privateKeyInfo = PrivateKeyInfo.getInstance(encoded);
            keySpecOid = (privateKeyInfo.getPrivateKeyAlgorithm().getParameters() instanceof ASN1ObjectIdentifier) ? ((ASN1ObjectIdentifier)privateKeyInfo.getPrivateKeyAlgorithm().getParameters()) : null;
            if(keySpecOid == null) {
                keySpecOid = privateKeyInfo.getPrivateKeyAlgorithm().getAlgorithm();
            }
            algorithmIdentifier = privateKeyInfo.getPrivateKeyAlgorithm();
        }else if("X.509".equalsIgnoreCase(key.getFormat())) {
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

    public Key getKey() {
        return key;
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
