/*
 * AsymSecureFile
 * https://ablog.jc-lab.net/186
 *
 *  This software may be modified and distributed under the terms
 *  of the Apache License 2.0.  See the LICENSE file for details.
 */

package kr.jclab.javautils.asymsecurefile.internal.jasf4.asn;

import kr.jclab.javautils.asymsecurefile.internal.jasf4.ChunkResolver;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

import java.util.Enumeration;

public class Asn1AsymAlgorithmIdentifierChunk extends Asn1AbstractChunk<AlgorithmIdentifier> {
    public static final ChunkId CHUNK_ID = ChunkId.AsymAlgorithmIdentifier;
    public static final Asn1AbstractChunkDataFactory<AlgorithmIdentifier> FACTORY = AlgorithmIdentifier::getInstance;

    @ChunkInitializer
    public static void init() {
        ChunkResolver.addChunkClass(CHUNK_ID, Asn1AsymAlgorithmIdentifierChunk.class, Asn1AsymAlgorithmIdentifierChunk::new);
    }

    public Asn1AsymAlgorithmIdentifierChunk(AlgorithmIdentifier data) {
        super(FACTORY, CHUNK_ID, new Asn1ChunkFlags(), data);
    }

    public Asn1AsymAlgorithmIdentifierChunk(Asn1ChunkFlags flags, AlgorithmIdentifier data) {
        super(FACTORY, CHUNK_ID, flags, data);
    }

    public Asn1AsymAlgorithmIdentifierChunk(Enumeration e) {
        super(FACTORY, e);
    }

    public static Asn1AsymAlgorithmIdentifierChunk getInstance(
            ASN1TaggedObject obj,
            boolean          explicit)
    {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static Asn1AsymAlgorithmIdentifierChunk getInstance(
            Object obj)
    {
        if (obj instanceof Asn1AsymAlgorithmIdentifierChunk)
        {
            return (Asn1AsymAlgorithmIdentifierChunk)obj;
        }

        if (obj != null)
        {
            return new Asn1AsymAlgorithmIdentifierChunk(ASN1Sequence.getInstance(obj).getObjects());
        }

        return null;
    }
}
