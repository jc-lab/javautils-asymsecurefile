/*
 * AsymSecureFile
 * https://ablog.jc-lab.net/186
 *
 *  This software may be modified and distributed under the terms
 *  of the Apache License 2.0.  See the LICENSE file for details.
 */

package kr.jclab.javautils.asymsecurefile.internal.signedsecurefile;

public enum HeaderCipherAlgorithm {
    NONE((byte)0, null, null),
    V1_RSA((byte)1, "v1_RSA", "RSA"),
    EC((byte)2, "EC", null),
    RSA((byte)3, "RSA", "RSA/ECB/PKCS1Padding");

    final private byte value;
    final private String algoName;
    final private String cipherName;

    HeaderCipherAlgorithm(byte value, String algoName, String cipherName) {
        this.value = value;
        this.algoName = algoName;
        this.cipherName = cipherName;
    }

    public final byte getValue() {
        return this.value;
    }

    public final String getAlgoName() {
        return this.algoName;
    }

    public String getCipherName() {
        return cipherName;
    }

    public static HeaderCipherAlgorithm findByName(String name) {
        for(HeaderCipherAlgorithm item : values()) {
            if(name.equalsIgnoreCase(item.getAlgoName()))
                return item;
        }
        return null;
    }
}
