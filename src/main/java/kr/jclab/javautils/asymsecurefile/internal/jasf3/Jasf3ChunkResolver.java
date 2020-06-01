package kr.jclab.javautils.asymsecurefile.internal.jasf3;

import kr.jclab.javautils.asymsecurefile.internal.deprecated.Chunk;

import java.lang.reflect.InvocationTargetException;
import java.util.HashMap;

public class Jasf3ChunkResolver {
    private final static HashMap<Byte, Class<? extends Chunk>> chunkClasses = new HashMap<>();

    static {
        chunkClasses.put(DefaultHeaderChunk.CHUNK_TYPE.value(), DefaultHeaderChunk.class);
        chunkClasses.put(AsymAlgorithmChunk.CHUNK_TYPE.value(), AsymAlgorithmChunk.class);
        chunkClasses.put(DataAlgorithmChunk.CHUNK_TYPE.value(), DataAlgorithmChunk.class);
        chunkClasses.put(EncryptedSeedKeyChunk.CHUNK_TYPE.value(), EncryptedSeedKeyChunk.class);
        chunkClasses.put(SeedKeyCheckChunk.CHUNK_TYPE.value(), SeedKeyCheckChunk.class);
        chunkClasses.put(DataIvChunk.CHUNK_TYPE.value(), DataIvChunk.class);
        chunkClasses.put(FooterChunk.CHUNK_TYPE.value(), FooterChunk.class);
    }

    public static Chunk parseChunk(byte primaryType, short userCode, short dataSize, byte[] data) {
        if((primaryType & 0x80) != 0) {
            return new RawUserChunk(primaryType, userCode, dataSize, data);
        }else {
            Class<? extends Chunk> chunkClazz = chunkClasses.get(primaryType);
            if(chunkClazz == null)
                return null;
            try {
                return chunkClazz.getDeclaredConstructor(new Class[] { Short.class, byte[].class }).newInstance(dataSize, data);
            } catch (InstantiationException | IllegalAccessException | NoSuchMethodException | InvocationTargetException e) {
                throw new RuntimeException(e);
            }
        }
    }
}
