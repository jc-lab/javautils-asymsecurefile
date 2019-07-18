/*
 * AsymSecureFile
 * https://ablog.jc-lab.net/186
 *
 *  This software may be modified and distributed under the terms
 *  of the Apache License 2.0.  See the LICENSE file for details.
 */

package kr.jclab.javautils.asymsecurefile.internal;

import kr.jclab.javautils.asymsecurefile.AsymAlgorithm;
import kr.jclab.javautils.asymsecurefile.NotSupportAlgorithmException;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;

import java.security.Key;
import java.security.interfaces.ECKey;
import java.security.interfaces.RSAKey;

public class AlgorithmInfo {
    private final AsymAlgorithm algorithm;
    private final ASN1ObjectIdentifier oid;
    private final int keySize;

    public AlgorithmInfo(Key key, AsymAlgorithm algorithm) throws NotSupportAlgorithmException {
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
        }else if("X.509".equalsIgnoreCase(key.getFormat())) {
            SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfo.getInstance(encoded);
            keySpecOid = (publicKeyInfo.getAlgorithm().getParameters() instanceof ASN1ObjectIdentifier) ? ((ASN1ObjectIdentifier)publicKeyInfo.getAlgorithm().getParameters()) : null;
            if(keySpecOid == null) {
                keySpecOid = publicKeyInfo.getAlgorithm().getAlgorithm();
            }
        }

        if(algorithm == null) {
            for (AsymAlgorithm item : AsymAlgorithm.values()) {
                if (keySpecOid.equals(item.getIdentifier()) || keySpecOid.on(item.getIdentifier())) {
                    algorithm = item;
                    break;
                }
            }

            /* Exceptional cases */
            if (algorithm == null) {
                if (keySpecOid.equals(X9ObjectIdentifiers.id_ecPublicKey)) {
                    algorithm = AsymAlgorithm.EC;
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

        this.algorithm = algorithm;
        this.oid = keySpecOid;
        this.keySize = keySize;
    }

    public AlgorithmInfo(AsymAlgorithm asymAlgorithm, int keySize, ASN1ObjectIdentifier oid) {
        this.algorithm = asymAlgorithm;
        this.keySize = keySize;
        this.oid = oid;
    }

    public AsymAlgorithm getAlgorithm() {
        return this.algorithm;
    }

    public ASN1ObjectIdentifier getOid() {
        return oid;
    }

    public int getKeySize() {
        return keySize;
    }
}
