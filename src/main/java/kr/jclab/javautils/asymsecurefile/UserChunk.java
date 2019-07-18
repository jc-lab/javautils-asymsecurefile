/*
 * AsymSecureFile
 * https://ablog.jc-lab.net/186
 *
 *  This software may be modified and distributed under the terms
 *  of the Apache License 2.0.  See the LICENSE file for details.
 */

package kr.jclab.javautils.asymsecurefile;

public class UserChunk extends Chunk {
    public UserChunk(byte primaryType, short userCode, short dataSize, byte[] data) {
        super((byte)(0x80 | primaryType), userCode, dataSize, data);
    }

    public UserChunk(Flag flag, short userCode, short dataSize, byte[] data) {
        super((byte)(0x80 | flag.value()), userCode, dataSize, data);
    }

    public Flag getFlag() {
        if((this.primaryType & 0x80) != 0) {
            byte value = (byte)(this.primaryType & 0x7F);
            for(Flag flag : Flag.values()) {
                if(flag.value() == value) {
                    return flag;
                }
            }
        }
        return null;
    }

    public short getUserCode() {
        return userCode;
    }
}
