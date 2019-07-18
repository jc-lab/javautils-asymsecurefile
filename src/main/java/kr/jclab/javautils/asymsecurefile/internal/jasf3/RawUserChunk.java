package kr.jclab.javautils.asymsecurefile.internal.jasf3;

import kr.jclab.javautils.asymsecurefile.UserChunk;

public class RawUserChunk extends UserChunk {
    public RawUserChunk(byte primaryType, short userCode, short dataSize, byte[] data) {
        super(primaryType, userCode, dataSize, data);
    }

    public RawUserChunk(RawUserChunk obj) {
        super(obj.primaryType, obj.userCode, obj.dataSize, obj.data);
    }
}
