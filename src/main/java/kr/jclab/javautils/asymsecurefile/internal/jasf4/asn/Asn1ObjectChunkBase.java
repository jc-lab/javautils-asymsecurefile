/*
 * AsymSecureFile
 * https://ablog.jc-lab.net/186
 *
 *  This software may be modified and distributed under the terms
 *  of the Apache License 2.0.  See the LICENSE file for details.
 */

package kr.jclab.javautils.asymsecurefile.internal.jasf4.asn;

import org.bouncycastle.asn1.*;

import java.util.Enumeration;

public abstract class Asn1ObjectChunkBase extends ASN1Object {
    private final int id;
    private final Asn1ChunkFlags flags;

    protected Asn1ObjectChunkBase(int id, Asn1ChunkFlags flags) {
        this.id = id;
        this.flags = flags;
    }

    protected Asn1ObjectChunkBase(ChunkId id, Asn1ChunkFlags flags) {
        this(id.getValue(), flags);
    }

    protected Asn1ObjectChunkBase(Enumeration e) {
        this.id = ASN1Integer.getInstance(e.nextElement()).getValue().intValue();
        this.flags = Asn1ChunkFlags.getInstance(e.nextElement());
    }

    public ChunkId getChunkId() {
        if(id >= ChunkId.CustomBegin.getValue()) {
            return ChunkId.CustomBegin;
        }
        return ChunkId.fromValue(id);
    }

    public int getRawId() {
        return id;
    }

    public Asn1ChunkFlags getFlags() {
        return new Asn1ChunkFlags(flags);
    }

    public abstract ASN1Object dataToASN1Primitive();

    @Override
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(new ASN1Integer(this.id));
        v.add(this.flags);
        v.add(this.dataToASN1Primitive());
        return new DERSequence(v);
    }
}
