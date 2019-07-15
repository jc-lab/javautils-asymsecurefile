/*
 * AsymSecureFile
 * https://ablog.jc-lab.net/186
 *
 *  This software may be modified and distributed under the terms
 *  of the Apache License 2.0.  See the LICENSE file for details.
 */

package kr.jclab.javautils.asymsecurefile;

public class Chunk {
    public enum Flag {
        EncryptedWithCustomKey((byte)0x01),
        SignedSignature((byte)0x02),
        EncryptedWithAuthEncKey((byte)0x03);

        private final byte value;
        Flag(byte value) {
            this.value = value;
        }
        public byte value() {
            return value;
        }
    }

    protected final byte primaryType;
    protected final short userCode;
    protected final short dataSize;
    protected final byte[] data;

    public Chunk(byte primaryType, short userCode, short dataSize, byte[] data) {
        this.primaryType = primaryType;
        this.userCode = userCode;
        this.dataSize = dataSize;
        this.data = data;
    }

    public Chunk(byte primaryType, byte[] data) {
        this.primaryType = primaryType;
        this.userCode = 0;
        this.dataSize = (short)data.length;
        this.data = data;
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

    public int getChunkId() {
        if((this.primaryType & 0x80) != 0) {
            return 0x800000 | (this.userCode & 0xFFFF);
        }
        return this.primaryType;
    }

    public byte getPrimaryType() {
        return primaryType;
    }

    public short getUserCode() {
        return userCode;
    }

    public short getDataSize() {
        return dataSize;
    }

    public byte[] getData() {
        return data;
    }
}
