/*
 * AsymSecureFile
 * https://ablog.jc-lab.net/186
 *
 *  This software may be modified and distributed under the terms
 *  of the Apache License 2.0.  See the LICENSE file for details.
 */

package kr.jclab.javautils.asymsecurefile.internal.jasf3;

import kr.jclab.javautils.asymsecurefile.Chunk;
import kr.jclab.javautils.asymsecurefile.InvalidFileException;

import java.util.Arrays;

public class EncryptedDataKeyChunk {
    // RSA : Encrypted by RSA/ECB/OEAP
    // EC  : EC Local Key Encoded
    private byte[] data;

    public EncryptedDataKeyChunk() {
    }

    public EncryptedDataKeyChunk(Chunk chunk) throws InvalidFileException {
        if(chunk == null)
            throw new InvalidFileException("Not exists EncryptedSeedKey");
        this.data = Arrays.copyOf(chunk.getData(), chunk.getDataSize());
    }

    public Chunk build() {
        return new Chunk(Jasf3ChunkType.ENCRYPTED_SEED_KEY.value(), this.data);
    }

    public byte[] data() {
        return this.data;
    }
    public EncryptedDataKeyChunk data(byte[] data) {
        this.data = data;
        return this;
    }
}
