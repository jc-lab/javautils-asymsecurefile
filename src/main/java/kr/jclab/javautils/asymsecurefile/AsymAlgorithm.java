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
    SECP192R1(new ASN1ObjectIdentifier[]{SECObjectIdentifiers.secp192r1, X9ObjectIdentifiers.prime192v1}, "EC", "secp192r1", "ECDSA"),
    SECP256R1(new ASN1ObjectIdentifier[]{SECObjectIdentifiers.secp256r1, X9ObjectIdentifiers.prime256v1}, "EC", "secp256r1", "ECDSA"),
    SECP521R1(new ASN1ObjectIdentifier[]{SECObjectIdentifiers.secp521r1}, "EC", "secp521r1", "ECDSA"),
    RSA(new ASN1ObjectIdentifier[] {PKCSObjectIdentifiers.rsaEncryption}, "RSA", null, "DSA");

    private final ASN1ObjectIdentifier[] identifiers;
    private final String algorithm;
    private final String spec;
    private final String signatureAlgorithm;
    AsymAlgorithm(ASN1ObjectIdentifier[] identifiers, String algorithm, String spec, String signatureAlgorithm) {
        this.identifiers = identifiers;
        this.algorithm = algorithm;
        this.spec = spec;
        this.signatureAlgorithm = signatureAlgorithm;
    }

    public ASN1ObjectIdentifier[] getIdentifiers() {
        return identifiers;
    }

    public String getAlgorithm() {
        return algorithm;
    }

    public String getSpec() {
        return spec;
    }

    public String getSignatureAlgorithm() {
        return signatureAlgorithm;
    }
}
