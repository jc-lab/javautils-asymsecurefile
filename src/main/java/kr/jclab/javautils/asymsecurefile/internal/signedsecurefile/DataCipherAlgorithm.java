/*
 * AsymSecureFile
 * https://ablog.jc-lab.net/186
 *
 *  This software may be modified and distributed under the terms
 *  of the Apache License 2.0.  See the LICENSE file for details.
 */

package kr.jclab.javautils.asymsecurefile.internal.signedsecurefile;

public enum DataCipherAlgorithm {
    NONE((byte)0, null), AES_CBC((byte)1, "AES/CBC/PKCS5Padding");

    final private byte value;
    final private String algoName;

    DataCipherAlgorithm(byte value, String algoName) {
        this.value = value;
        this.algoName = algoName;
    }

    public final byte getValue() {
        return this.value;
    }

    public final String getAlgoName() {
        return this.algoName;
    }
}
