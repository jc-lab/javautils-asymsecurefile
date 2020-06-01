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
import org.bouncycastle.asn1.cms.ContentInfo;

import java.util.Enumeration;

public class Asn1TimestampChunk extends Asn1AbstractChunk<ContentInfo> {
    public static final ChunkId CHUNK_ID = ChunkId.Timestamp;
    public static final Asn1AbstractChunkDataFactory<ContentInfo> FACTORY = ContentInfo::getInstance;

    @ChunkInitializer
    public static void init() {
        ChunkResolver.addChunkClass(CHUNK_ID, Asn1TimestampChunk.class, Asn1TimestampChunk::new);
    }

    public Asn1TimestampChunk(ContentInfo data) {
        super(FACTORY, CHUNK_ID, new Asn1ChunkFlags(), data);
    }

    public Asn1TimestampChunk(Enumeration e) {
        super(FACTORY, e);
    }

    public static Asn1TimestampChunk getInstance(
            ASN1TaggedObject obj,
            boolean          explicit)
    {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static Asn1TimestampChunk getInstance(
            Object obj)
    {
        if (obj instanceof Asn1TimestampChunk)
        {
            return (Asn1TimestampChunk)obj;
        }

        if (obj != null)
        {
            return new Asn1TimestampChunk(ASN1Sequence.getInstance(obj).getObjects());
        }

        return null;
    }
}
