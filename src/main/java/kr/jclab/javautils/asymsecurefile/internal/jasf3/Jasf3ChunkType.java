/*
 * AsymSecureFile
 * https://ablog.jc-lab.net/186
 *
 *  This software may be modified and distributed under the terms
 *  of the Apache License 2.0.  See the LICENSE file for details.
 */

package kr.jclab.javautils.asymsecurefile.internal.jasf3;

public enum Jasf3ChunkType {
    DEFAULT_HEADER((byte)0x01),
    ASYM_ALGORITHM((byte)0x02), // OID
    DATA_ALGORITHM((byte)0x03), // OID
    ENCRYPTED_SEED_KEY((byte)0x04),
    SEED_KEY_CHECK((byte)0x05),
    DATA_IV((byte)0x11), // Block size
    DATA_STREAM((byte)0x70),
    FOOTER_FINGERPRINT((byte)0x7A);

    private final byte value;

    Jasf3ChunkType(byte value) {
        this.value = value;
    }

    public byte value() {
        return value;
    }
}
