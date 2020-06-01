package kr.jclab.javautils.asymsecurefile.internal.jasf3;

import kr.jclab.javautils.asymsecurefile.internal.deprecated.Chunk;

public class RawUserChunk extends Chunk {
    public RawUserChunk(byte primaryType, short userCode, short dataSize, byte[] data) {
        super(primaryType, userCode, dataSize, data);
    }

    public RawUserChunk(RawUserChunk obj) {
        super(obj.primaryType, obj.userCode, obj.dataSize, obj.data);
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
}
