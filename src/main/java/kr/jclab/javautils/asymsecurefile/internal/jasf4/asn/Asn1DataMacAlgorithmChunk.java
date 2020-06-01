/*
 * AsymSecureFile
 * https://ablog.jc-lab.net/186
 *
 *  This software may be modified and distributed under the terms
 *  of the Apache License 2.0.  See the LICENSE file for details.
 */

package kr.jclab.javautils.asymsecurefile.internal.jasf4.asn;

import kr.jclab.javautils.asymsecurefile.internal.jasf4.ChunkResolver;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

import java.util.Enumeration;

public class Asn1DataMacAlgorithmChunk extends Asn1AbstractChunk<AlgorithmIdentifier> {
    public static final ChunkId CHUNK_ID = ChunkId.DataMacAlgorithm;
    public static final Asn1AbstractChunkDataFactory<AlgorithmIdentifier> FACTORY = AlgorithmIdentifier::getInstance;

    @ChunkInitializer
    public static void init() {
        ChunkResolver.addChunkClass(CHUNK_ID, Asn1DataMacAlgorithmChunk.class, Asn1DataMacAlgorithmChunk::new);
    }

    public Asn1DataMacAlgorithmChunk(AlgorithmIdentifier data) {
        super(FACTORY, CHUNK_ID, new Asn1ChunkFlags(), data);
    }

    public Asn1DataMacAlgorithmChunk(Enumeration e) {
        super(FACTORY, e);
    }

    public static Asn1DataMacAlgorithmChunk getInstance(
            ASN1TaggedObject obj,
            boolean          explicit)
    {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static Asn1DataMacAlgorithmChunk getInstance(
            Object obj)
    {
        if (obj instanceof Asn1DataMacAlgorithmChunk)
        {
            return (Asn1DataMacAlgorithmChunk)obj;
        }

        if (obj != null)
        {
            return new Asn1DataMacAlgorithmChunk(ASN1Sequence.getInstance(obj).getObjects());
        }

        return null;
    }
}
