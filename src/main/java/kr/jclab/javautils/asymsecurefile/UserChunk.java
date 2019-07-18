/*
 * AsymSecureFile
 * https://ablog.jc-lab.net/186
 *
 *  This software may be modified and distributed under the terms
 *  of the Apache License 2.0.  See the LICENSE file for details.
 */

package kr.jclab.javautils.asymsecurefile;

public class UserChunk extends Chunk {
    protected UserChunk(byte flag, short userCode, short dataSize, byte[] data) {
        super((byte)(0x80 | flag), userCode, dataSize, data);
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

    public static final Builder builder() {
        return new Builder();
    }

    public static final class Builder {
        protected Flag flag;
        protected short userCode;
        protected short dataSize = 0;
        protected byte[] data;

        private Builder() {
        }

        public static Builder anUserChunk() {
            return new Builder();
        }

        public Builder withFlag(Flag flag) {
            switch (flag) {
                case EncryptedWithCustomKey:
                    throw new IllegalArgumentException("Not support yet");
                case SignedSignature:
                    throw new IllegalArgumentException("Not support yet");
            }
            this.flag = flag;
            return this;
        }

        public Builder withUserCode(short userCode) {
            this.userCode = userCode;
            return this;
        }

        public Builder withDataSize(short dataSize) {
            this.dataSize = dataSize;
            return this;
        }

        public Builder withData(byte[] data) {
            this.data = data;
            return this;
        }

        public UserChunk build() {
            if(dataSize <= 0 && data != null)
                dataSize = (short)data.length;
            return new UserChunk(flag.value(), userCode, dataSize, data);
        }
    }
}
