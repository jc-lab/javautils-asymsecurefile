/*
 * AsymSecureFile
 * https://ablog.jc-lab.net/186
 *
 *  This software may be modified and distributed under the terms
 *  of the Apache License 2.0.  See the LICENSE file for details.
 */

package kr.jclab.javautils.asymsecurefile.internal.jasf3;

import kr.jclab.javautils.asymsecurefile.internal.deprecated.Chunk;

public class EncryptedSeedKeyChunk extends Chunk {
    public static final Jasf3ChunkType CHUNK_TYPE = Jasf3ChunkType.ENCRYPTED_SEED_KEY;
    // RSA : Encrypted by RSA/ECB/OEAP
    // EC  : EC Local Key Encoded

    public EncryptedSeedKeyChunk(byte[] data) {
        super(CHUNK_TYPE.value(), (short)0, (short)data.length, data);
    }

    public EncryptedSeedKeyChunk(Short dataSize, byte[] data) {
        super(CHUNK_TYPE.value(), (short)0, dataSize, data);
    }

    public byte[] data() {
        return this.data;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static final class Builder {
        private byte[] data;

        public Builder withData(byte[] data) {
            this.data = data;
            return this;
        }

        public EncryptedSeedKeyChunk build() {
            return new EncryptedSeedKeyChunk(this.data);
        }
    }
}
