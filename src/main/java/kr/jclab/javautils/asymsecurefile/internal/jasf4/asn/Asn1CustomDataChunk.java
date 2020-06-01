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

public class Asn1CustomDataChunk extends Asn1AbstractChunk<ASN1OctetString> {
    private static final ChunkId CHUNK_BEGIN = ChunkId.CustomBegin;
    public static final Asn1AbstractChunkDataFactory<ASN1OctetString> FACTORY = ASN1OctetString::getInstance;

    @ChunkInitializer
    public static void init() {
        ChunkResolver.addChunkClass(CHUNK_BEGIN, Asn1CustomDataChunk.class, Asn1CustomDataChunk::new);
    }

    private static Asn1ChunkFlags convertFlags(Asn1ChunkFlags input) {
        Asn1ChunkFlags flags = new Asn1ChunkFlags(input.getValue());
        flags.encryptWithAuthKey(true);
        return flags;
    }

    public Asn1CustomDataChunk(int index, Asn1ChunkFlags flags, byte[] data) {
        super(FACTORY, CHUNK_BEGIN.getValue() + index, flags, new DEROctetString(data));
    }

    public Asn1CustomDataChunk(Enumeration e) {
        super(FACTORY, e);
    }

    public byte[] getBytesData() {
        return this.data.getOctets();
    }

    public static Asn1CustomDataChunk getInstance(
            ASN1TaggedObject obj,
            boolean          explicit)
    {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static Asn1CustomDataChunk getInstance(
            Object obj)
    {
        if (obj instanceof Asn1CustomDataChunk)
        {
            return (Asn1CustomDataChunk)obj;
        }

        if (obj != null)
        {
            return new Asn1CustomDataChunk(ASN1Sequence.getInstance(obj).getObjects());
        }

        return null;
    }
}
