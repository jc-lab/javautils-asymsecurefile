/*
 * AsymSecureFile
 * https://ablog.jc-lab.net/186
 *
 *  This software may be modified and distributed under the terms
 *  of the Apache License 2.0.  See the LICENSE file for details.
 */

package kr.jclab.javautils.asymsecurefile.internal;

import kr.jclab.javautils.asymsecurefile.AsymAlgorithmOld;
import kr.jclab.javautils.asymsecurefile.AsymmetricKeyObject;
import kr.jclab.javautils.asymsecurefile.NotSupportAlgorithmException;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.sec.SECObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;

import java.security.Key;
import java.security.interfaces.ECKey;
import java.security.interfaces.RSAKey;

public class AlgorithmInfo {
    private final AsymAlgorithmOld algorithmOld;
    private final ASN1ObjectIdentifier oid;
    private final int keySize;

    private final AlgorithmIdentifier algorithmIdentifier;

    public AlgorithmInfo(AsymmetricKeyObject keyObject, Key key) throws NotSupportAlgorithmException {
        int keySize = 0;
        AsymAlgorithmOld algorithm = null;
        this.algorithmIdentifier = keyObject.getAlgorithmIdentifier();
        if(
                AsymmetricAlgorithmType.ec.equals(keyObject.getAlgorithmType()) ||
                        AsymmetricAlgorithmType.x448.equals(keyObject.getAlgorithmType()) ||
                        AsymmetricAlgorithmType.x25519.equals(keyObject.getAlgorithmType()) ||
                        AsymmetricAlgorithmType.edwards.equals(keyObject.getAlgorithmType())
        ) {
            algorithm = AsymAlgorithmOld.EC;
        }else if(AsymmetricAlgorithmType.rsa.equals(keyObject.getAlgorithmType())) {
            algorithm = AsymAlgorithmOld.RSA;
        }

        switch (algorithm) {
            case EC:
                keySize = ((ECKey)key).getParams().getCurve().getField().getFieldSize();
                break;
            case RSA:
                keySize = ((RSAKey)key).getModulus().bitLength();
                break;
        }

        this.algorithmOld = algorithm;
        this.oid = keyObject.getAlgorithmIdentifier().getAlgorithm();
        this.keySize = keySize;
    }

    public AlgorithmInfo(AlgorithmIdentifier algorithmIdentifier, int defaultKeySize) {
        this.algorithmIdentifier = algorithmIdentifier;
        this.oid = algorithmIdentifier.getAlgorithm();
        if(this.algorithmIdentifier.getAlgorithm().on(SECObjectIdentifiers.ellipticCurve)) {
            this.algorithmOld = AsymAlgorithmOld.EC;
            this.keySize = 0;
        }else if(this.algorithmIdentifier.getAlgorithm().on(PKCSObjectIdentifiers.pkcs_1)) {
            this.algorithmOld = AsymAlgorithmOld.RSA;
            this.keySize = defaultKeySize;
        }else{
            this.algorithmOld = null;
            this.keySize = defaultKeySize;
        }
    }

    /**
     * @param key
     * @param algorithm
     * @throws NotSupportAlgorithmException
     * @deprecated
     */
    public AlgorithmInfo(Key key, AsymAlgorithmOld algorithm) throws NotSupportAlgorithmException {
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
            this.algorithmIdentifier = privateKeyInfo.getPrivateKeyAlgorithm();
        }else if("X.509".equalsIgnoreCase(key.getFormat())) {
            SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfo.getInstance(encoded);
            keySpecOid = (publicKeyInfo.getAlgorithm().getParameters() instanceof ASN1ObjectIdentifier) ? ((ASN1ObjectIdentifier)publicKeyInfo.getAlgorithm().getParameters()) : null;
            if(keySpecOid == null) {
                keySpecOid = publicKeyInfo.getAlgorithm().getAlgorithm();
            }
            this.algorithmIdentifier = publicKeyInfo.getAlgorithm();
        }else{
            this.algorithmIdentifier = null;
        }

        if(algorithm == null) {
            for (AsymAlgorithmOld item : AsymAlgorithmOld.values()) {
                if (keySpecOid.equals(item.getIdentifier()) || keySpecOid.on(item.getIdentifier())) {
                    algorithm = item;
                    break;
                }
            }

            /* Exceptional cases */
            if (algorithm == null) {
                if (keySpecOid.equals(X9ObjectIdentifiers.id_ecPublicKey)) {
                    algorithm = AsymAlgorithmOld.EC;
                }
            }

            if (algorithm == null) {
                throw new NotSupportAlgorithmException("format=" + key.getFormat() + ", keySpecOid" + keySpecOid.getId());
            }
        }

        switch (algorithm) {
            case EC:
                keySize = ((ECKey)key).getParams().getCurve().getField().getFieldSize();
                break;
            case RSA:
                keySize = ((RSAKey)key).getModulus().bitLength();
                break;
        }

        this.algorithmOld = algorithm;
        this.oid = keySpecOid;
        this.keySize = keySize;
    }

    /**
     *
     * @param asymAlgorithm
     * @param keySize
     * @param oid
     * @deprecated
     */
    public AlgorithmInfo(AsymAlgorithmOld asymAlgorithm, int keySize, ASN1ObjectIdentifier oid) {
        this.algorithmOld = asymAlgorithm;
        this.keySize = keySize;
        this.oid = oid;
        this.algorithmIdentifier = null;
    }

    public AsymAlgorithmOld getAlgorithmOld() {
        return this.algorithmOld;
    }

    public ASN1ObjectIdentifier getOid() {
        return oid;
    }

    public int getKeySize() {
        return keySize;
    }

    public AlgorithmIdentifier getAlgorithmIdentifier() {
        return algorithmIdentifier;
    }
}
