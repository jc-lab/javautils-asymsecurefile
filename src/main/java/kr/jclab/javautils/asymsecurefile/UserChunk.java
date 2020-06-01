/*
 * AsymSecureFile
 * https://ablog.jc-lab.net/186
 *
 *  This software may be modified and distributed under the terms
 *  of the Apache License 2.0.  See the LICENSE file for details.
 */

package kr.jclab.javautils.asymsecurefile;

public class UserChunk {
    public enum Flag {
        EncryptWithAuthKey(0x0001);

        private final int value;
        Flag(int value) {
            this.value = value;
        }
        int value() {
            return this.value;
        }
    }

    private final int flag;
    private final int userCode;
    private final int dataSize;
    private final byte[] data;

    public UserChunk(int flag, int userCode, int dataSize, byte[] data) {
        this.flag = flag;
        this.userCode = userCode;
        this.dataSize = dataSize;
        this.data = data;
    }

    public int getFlag() {
        return flag;
    }

    public int getUserCode() {
        return userCode;
    }

    public int getDataSize() {
        return dataSize;
    }

    public byte[] getData() {
        return data;
    }

    public boolean hasFlag(Flag flag) {
        return (this.flag & flag.value()) != 0;
    }

    public static final Builder builder() {
        return new Builder();
    }

    public static final class Builder {
        protected int flag = 0;
        protected int userCode = 0;
        protected int dataSize = 0;
        protected byte[] data;

        private Builder() {
        }

        public static Builder anUserChunk() {
            return new Builder();
        }

        public Builder withFlag(Flag flag) {
            this.flag |= flag.value();
            return this;
        }

        public Builder withUserCode(int userCode) {
            this.userCode = userCode;
            return this;
        }

        public Builder withDataSize(int dataSize) {
            this.dataSize = dataSize;
            return this;
        }

        public Builder withData(byte[] data) {
            this.data = data;
            return this;
        }

        public Builder encryptWithAuthKey() {
            return this.withFlag(Flag.EncryptWithAuthKey);
        }

        public UserChunk build() {
            if(dataSize <= 0 && data != null)
                dataSize = (short)data.length;
            return new UserChunk(flag, userCode, dataSize, data);
        }
    }
}
