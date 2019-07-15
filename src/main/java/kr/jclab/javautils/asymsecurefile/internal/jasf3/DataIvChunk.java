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

public class DataIvChunk {
    private byte[] data = null;

    public DataIvChunk() {
    }

    public DataIvChunk(Chunk chunk) throws InvalidFileException {
        if(chunk == null)
            throw new InvalidFileException("Not exists DataIv");
        if(chunk.getDataSize() < 1) {
            throw new InvalidFileException("Invalid DataIv");
        }
        this.data = chunk.getData();
        if(this.data.length != chunk.getDataSize())
            this.data = Arrays.copyOf(this.data, chunk.getDataSize());
    }

    public Chunk build() {
        return new Chunk(Jasf3ChunkType.DATA_IV.value(), this.data);
    }

    public byte[] data() {
        return this.data;
    }
    public DataIvChunk data(byte[] data) {
        this.data = data;
        return this;
    }
}
