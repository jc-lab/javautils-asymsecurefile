/*
 * AsymSecureFile
 * https://ablog.jc-lab.net/186
 *
 *  This software may be modified and distributed under the terms
 *  of the Apache License 2.0.  See the LICENSE file for details.
 */

package kr.jclab.javautils.asymsecurefile;

public enum OperationType {
    SIGN((byte)1),
    PUBLIC_ENCRYPT((byte)2);

    private byte value;
    OperationType(byte value) {
        this.value = value;
    }
    public byte value() {
        return value;
    }

    public static OperationType valueOf(int value) {
        for(OperationType item : values()) {
            if(item.value == value)
                return item;
        }
        return null;
    }
}
