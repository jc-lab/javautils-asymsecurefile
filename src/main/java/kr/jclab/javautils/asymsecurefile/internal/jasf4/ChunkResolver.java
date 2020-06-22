/*
 * AsymSecureFile
 * https://ablog.jc-lab.net/186
 *
 *  This software may be modified and distributed under the terms
 *  of the Apache License 2.0.  See the LICENSE file for details.
 */

package kr.jclab.javautils.asymsecurefile.internal.jasf4;

import kr.jclab.javautils.asymsecurefile.internal.jasf4.asn.*;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;

public class ChunkResolver {
    public interface IGetInstanceType<T> {
        T getInstance(Enumeration e);
    }

    private static class ChunkHolder {
        public final Class<? extends Asn1ObjectChunkBase> clazz;
        public final IGetInstanceType<? extends Asn1ObjectChunkBase> getInstanceFunction;

        public ChunkHolder(Class<? extends Asn1ObjectChunkBase> clazz, IGetInstanceType<? extends Asn1ObjectChunkBase> getInstanceFunction) {
            this.clazz = clazz;
            this.getInstanceFunction = getInstanceFunction;
        }
    }

    public static <T extends Asn1ObjectChunkBase> void addChunkClass(ChunkId chunkId, Class<T> clazz, IGetInstanceType<T> getInstanceFunction) {
        SingletoneHolder.CHUNK_MAP.computeIfAbsent(chunkId, (k) -> new ChunkHolder(clazz, getInstanceFunction));
    }

    public static Asn1ObjectChunkBase parseChunk(Object o) {
        ASN1Sequence sequence = ASN1Sequence.getInstance(o);
        int id = ASN1Integer.getInstance(sequence.getObjectAt(0)).intValueExact();
        Asn1ChunkFlags flags = new Asn1ChunkFlags(ASN1Integer.getInstance(sequence.getObjectAt(1)).intValueExact());
        ASN1Encodable dataPart = sequence.getObjectAt(2);
        ChunkHolder chunkHolder = (id >= ChunkId.CustomBegin.getValue()) ?
                SingletoneHolder.CHUNK_MAP.get(ChunkId.CustomBegin) : SingletoneHolder.CHUNK_MAP.get(ChunkId.fromValue(id));
        if (chunkHolder == null) {
            return null;
        }
        if(flags.isEncryptWithAuthKey()) {
            return new Asn1AbstractEncryptedChunk<>(chunkHolder.getInstanceFunction, id, flags, ASN1OctetString.getInstance(dataPart));
        }
        return chunkHolder.getInstanceFunction.getInstance(sequence.getObjects());
    }

    private static class SingletoneHolder {
        public static Map<ChunkId, ChunkHolder> CHUNK_MAP = new HashMap<>();

        private static void invokeChunkInitializer(Class<? extends Asn1ObjectChunkBase> clazz) {
            for (Method method : clazz.getDeclaredMethods()) {
                if(method.getAnnotation(ChunkInitializer.class) != null) {
                    try {
                        method.invoke(null);
                    } catch (IllegalAccessException | InvocationTargetException e) {
                        e.printStackTrace();
                    }
                    return ;
                }
            }
        }

        static {
            invokeChunkInitializer(Asn1AbstractChunk.class);
            invokeChunkInitializer(Asn1AbstractEncryptedChunk.class);
            invokeChunkInitializer(Asn1AsymAlgorithmIdentifierChunk.class);
            invokeChunkInitializer(Asn1AuthKeyCheckChunk.class);
            invokeChunkInitializer(Asn1CustomDataChunk.class);
            invokeChunkInitializer(Asn1DataChunk.class);
            invokeChunkInitializer(Asn1DataCryptoAlgorithmParameterSpecChunk.class);
            invokeChunkInitializer(Asn1DataKeyInfoChunk.class);
            invokeChunkInitializer(Asn1DataMacAlgorithmChunk.class);
            invokeChunkInitializer(Asn1DefaultHeaderChunk.class);
            invokeChunkInitializer(Asn1DHCheckDataChunk.class);
            invokeChunkInitializer(Asn1EncryptedChunk.class);
            invokeChunkInitializer(Asn1EncryptedDataKeyInfoChunk.class);
            invokeChunkInitializer(Asn1EphemeralECPublicKeyChunk.class);
            invokeChunkInitializer(Asn1FingerprintChunk.class);
            invokeChunkInitializer(Asn1MacOfEncryptedDataChunk.class);
            invokeChunkInitializer(Asn1SignedFingerprintChunk.class);
            invokeChunkInitializer(Asn1TimestampChunk.class);
        }
    }
}
