/*
 * AsymSecureFile
 * https://ablog.jc-lab.net/186
 *
 *  This software may be modified and distributed under the terms
 *  of the Apache License 2.0.  See the LICENSE file for details.
 */

package kr.jclab.javautils.asymsecurefile.internal.jasf4.asn;

import kr.jclab.javautils.asymsecurefile.internal.jasf4.ChunkResolver;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DEROctetString;

import java.util.Enumeration;

public class Asn1DHCheckDataChunk extends Asn1AbstractChunk<ASN1OctetString> {
    public static final ChunkId CHUNK_ID = ChunkId.DHCheckData;
    public static final Asn1AbstractChunkDataFactory<ASN1OctetString> FACTORY = ASN1OctetString::getInstance;

    @ChunkInitializer
    public static void init() {
        ChunkResolver.addChunkClass(CHUNK_ID, Asn1DHCheckDataChunk.class, Asn1DHCheckDataChunk::new);
    }

    public Asn1DHCheckDataChunk(byte[] data) {
        super(FACTORY, CHUNK_ID, new Asn1ChunkFlags(), new DEROctetString(data));
    }

    public Asn1DHCheckDataChunk(Enumeration e) {
        super(FACTORY, e);
    }

    public static Asn1DHCheckDataChunk getInstance(
            ASN1TaggedObject obj,
            boolean          explicit)
    {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static Asn1DHCheckDataChunk getInstance(
            Object obj)
    {
        if (obj instanceof Asn1DHCheckDataChunk)
        {
            return (Asn1DHCheckDataChunk)obj;
        }

        if (obj != null)
        {
            return new Asn1DHCheckDataChunk(ASN1Sequence.getInstance(obj).getObjects());
        }

        return null;
    }

    public byte[] getBytesData() {
        return this.data.getOctets();
    }
}
