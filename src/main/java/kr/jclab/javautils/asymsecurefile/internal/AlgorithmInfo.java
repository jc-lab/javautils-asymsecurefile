/*
 * AsymSecureFile
 * https://ablog.jc-lab.net/186
 *
 *  This software may be modified and distributed under the terms
 *  of the Apache License 2.0.  See the LICENSE file for details.
 */

package kr.jclab.javautils.asymsecurefile.internal;

import kr.jclab.javautils.asymsecurefile.AsymAlgorithm;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;

import java.security.Key;

public class AlgorithmInfo {
    private final AsymAlgorithm algorithm;
    private final ASN1ObjectIdentifier oid;

    public AlgorithmInfo(Key key) {
        AsymAlgorithm algorithm = null;
        byte[] encoded = key.getEncoded();
        ASN1ObjectIdentifier keySpecOid = null;
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
        for(AsymAlgorithm item : AsymAlgorithm.values()) {
            for(ASN1ObjectIdentifier oid : item.getIdentifiers()) {
                if(oid.equals(keySpecOid)) {
                    algorithm = item;
                    break;
                }
            }
            if(algorithm != null)
                break;
        }
        this.algorithm = algorithm;
        this.oid = keySpecOid;
    }

    public AlgorithmInfo(ASN1ObjectIdentifier keySpecOid) {
        AsymAlgorithm algorithm = null;
        for(AsymAlgorithm item : AsymAlgorithm.values()) {
            for(ASN1ObjectIdentifier oid : item.getIdentifiers()) {
                if(oid.equals(keySpecOid)) {
                    algorithm = item;
                    break;
                }
            }
            if(algorithm != null)
                break;
        }
        this.algorithm = algorithm;
        this.oid = keySpecOid;
    }

    public AsymAlgorithm getAlgorithm() {
        return this.algorithm;
    }

    public ASN1ObjectIdentifier getOid() {
        return oid;
    }
}
