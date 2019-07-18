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

public class DataIvChunk extends Chunk {
    public static final Jasf3ChunkType CHUNK_TYPE = Jasf3ChunkType.DATA_IV;
    private final byte[] iv;

    public DataIvChunk(byte[] iv) {
        super(CHUNK_TYPE.value(), (short)0, (short)iv.length, iv);
        this.iv = Arrays.copyOf(iv, iv.length);
    }

    public DataIvChunk(Short dataSize, byte[] data) throws InvalidFileException {
        super(CHUNK_TYPE.value(), (short)0, (short)data.length, data);
        if(dataSize < 1) {
            throw new InvalidFileException("Invalid DataIv");
        }
        this.iv = Arrays.copyOf(data, dataSize);
    }

    public byte[] getIv() {
        return this.iv;
    }

    public static final Builder builder() {
        return new Builder();
    }

    public static final class Builder {
        private byte[] iv;

        public Builder withIv(byte[] iv) {
            this.iv = iv;
            return this;
        }

        public DataIvChunk build() {
            return new DataIvChunk(this.iv);
        }
    }
}
