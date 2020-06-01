/*
 * AsymSecureFile
 * https://ablog.jc-lab.net/186
 *
 *  This software may be modified and distributed under the terms
 *  of the Apache License 2.0.  See the LICENSE file for details.
 */

package kr.jclab.javautils.asymsecurefile.internal.jasf4.asn;

import kr.jclab.javautils.asymsecurefile.internal.jasf4.ChunkResolver;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;

import java.util.Enumeration;

public class Asn1DataCryptoAlgorithmParameterSpecChunk<T extends ASN1Object> extends Asn1AbstractChunk<T> {
    public static final ChunkId CHUNK_ID = ChunkId.DataCryptoAlgorithmParameterSpec;
    private final Class<T> clazz;

    @ChunkInitializer
    public static void init() {
        ChunkResolver.addChunkClass(CHUNK_ID, Asn1DataCryptoAlgorithmParameterSpecChunk.class, Asn1DataCryptoAlgorithmParameterSpecChunk::getInstance);
    }

    public Asn1DataCryptoAlgorithmParameterSpecChunk(Class<T> clazz, Asn1AbstractChunkDataFactory<T> factory, Asn1ChunkFlags flags, T data) {
        super(factory, CHUNK_ID, new Asn1ChunkFlags(), data);
        this.clazz = clazz;
    }

    public Asn1DataCryptoAlgorithmParameterSpecChunk(Class<T> clazz, Asn1AbstractChunkDataFactory<T> factory, T data) {
        super(factory, CHUNK_ID, new Asn1ChunkFlags(), data);
        this.clazz = clazz;
    }

    public Asn1DataCryptoAlgorithmParameterSpecChunk(Class<T> clazz, Asn1AbstractChunkDataFactory<T> factory, Enumeration e) {
        super(factory, e);
        this.clazz = clazz;
    }

    public Class<T> getDataClass() {
        return this.clazz;
    }

    private static Asn1DataCryptoAlgorithmParameterSpecChunk<ASN1Object> getInstance(Object o) {
        if(o instanceof Enumeration) {
            Enumeration enumeration = (Enumeration)o;
            int chunkId = ASN1Integer.getInstance(enumeration.nextElement()).intValueExact();
            Asn1ChunkFlags flags = new Asn1ChunkFlags(ASN1Integer.getInstance(enumeration.nextElement()).intValueExact());
            return new Asn1DataCryptoAlgorithmParameterSpecChunk(ASN1Object.class, t -> (ASN1Object)t, flags, (ASN1Object)enumeration.nextElement());
        }
        return null;
    }

    public static <T extends ASN1Object> Asn1DataCryptoAlgorithmParameterSpecChunk<T> getInstance(
            Class<T> clazz,
            Asn1AbstractChunkDataFactory<T> factory,
            ASN1TaggedObject obj,
            boolean          explicit)
    {
        return getInstance(clazz, factory, ASN1Sequence.getInstance(obj, explicit));
    }

    public static <T extends ASN1Object> Asn1DataCryptoAlgorithmParameterSpecChunk<T> getInstance(
            Class<T> clazz,
            Asn1AbstractChunkDataFactory<T> factory,
            Object obj)
    {
        if (obj instanceof Asn1DataCryptoAlgorithmParameterSpecChunk)
        {
            if(clazz.isAssignableFrom(((Asn1DataCryptoAlgorithmParameterSpecChunk<?>)obj).getDataClass())) {
                return ((Asn1DataCryptoAlgorithmParameterSpecChunk<T>)obj);
            }
            return null;
        }

        if (obj != null)
        {
            return new Asn1DataCryptoAlgorithmParameterSpecChunk<T>(clazz, factory, ASN1Sequence.getInstance(obj).getObjects());
        }

        return null;
    }
}
