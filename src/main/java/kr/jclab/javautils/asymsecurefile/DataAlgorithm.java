/*
 * AsymSecureFile
 * https://ablog.jc-lab.net/186
 *
 *  This software may be modified and distributed under the terms
 *  of the Apache License 2.0.  See the LICENSE file for details.
 */

package kr.jclab.javautils.asymsecurefile;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

public enum DataAlgorithm {
    AES256_GCM(NISTObjectIdentifiers.id_aes256_GCM, "AES/GCM/NOPADDING", 32, true);

    private final ASN1ObjectIdentifier identifier;
    private final String algorithm;
    private final int keySize;
    private final boolean containMac;
    DataAlgorithm(ASN1ObjectIdentifier identifier, String algorithm, int keySize, boolean containMac) {
        this.identifier = identifier;
        this.algorithm = algorithm;
        this.keySize = keySize;
        this.containMac = containMac;
    }
    public ASN1ObjectIdentifier getIdentifier() {
        return identifier;
    }

    public String getAlgorithm() {
        return algorithm;
    }

    public int getKeySize() {
        return keySize;
    }

    public boolean isContainMac() {
        return containMac;
    }
}
