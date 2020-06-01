package kr.jclab.javautils.asymsecurefile.internal.jasf3;

import kr.jclab.javautils.asymsecurefile.internal.deprecated.Chunk;

public class RawChunk extends Chunk {
    public RawChunk(byte primaryType, short userCode, short dataSize, byte[] data) {
        super(primaryType, userCode, dataSize, data);
    }
}
