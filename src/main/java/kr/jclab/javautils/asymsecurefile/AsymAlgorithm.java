/*
 * AsymSecureFile
 * https://ablog.jc-lab.net/186
 *
 *  This software may be modified and distributed under the terms
 *  of the Apache License 2.0.  See the LICENSE file for details.
 */

package kr.jclab.javautils.asymsecurefile;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.sec.SECObjectIdentifiers;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;

public enum AsymAlgorithm {
    EC((byte)0x11, SECObjectIdentifiers.ellipticCurve, "EC", "ECDSA"),
    PRIME((byte)0x12, X9ObjectIdentifiers.primeCurve, "EC", "ECDSA"),
    RSA((byte)0x20, PKCSObjectIdentifiers.rsaEncryption, "RSA", "DSA");

    private final byte keyType;
    private final ASN1ObjectIdentifier identifier;
    private final String algorithm;
    private final String signatureAlgorithm;
    AsymAlgorithm(byte keyType, ASN1ObjectIdentifier identifier, String algorithm, String signatureAlgorithm) {
        this.keyType = keyType;
        this.identifier = identifier;
        this.algorithm = algorithm;
        this.signatureAlgorithm = signatureAlgorithm;
    }

    public byte getKeyType() {
        return keyType;
    }

    public ASN1ObjectIdentifier getIdentifier() {
        return identifier;
    }

    public String getAlgorithm() {
        return algorithm;
    }

    public String getSignatureAlgorithm() {
        return signatureAlgorithm;
    }
}
