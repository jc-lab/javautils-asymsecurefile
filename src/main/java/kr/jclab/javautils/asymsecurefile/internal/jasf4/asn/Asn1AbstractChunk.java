/*
 * AsymSecureFile
 * https://ablog.jc-lab.net/186
 *
 *  This software may be modified and distributed under the terms
 *  of the Apache License 2.0.  See the LICENSE file for details.
 */

package kr.jclab.javautils.asymsecurefile.internal.jasf4.asn;

import org.bouncycastle.asn1.ASN1Object;

import java.util.Enumeration;

public class Asn1AbstractChunk<T extends ASN1Object> extends Asn1ObjectChunkBase {
    private final Asn1AbstractChunkDataFactory<T> factory;
    protected final T data;

    public Asn1AbstractChunk(Asn1AbstractChunkDataFactory<T> factory, ChunkId id, Asn1ChunkFlags flags, T data) {
        super(id, flags);
        this.factory = factory;
        this.data = data;
    }

    public Asn1AbstractChunk(Asn1AbstractChunkDataFactory<T> factory, int id, Asn1ChunkFlags flags, T data) {
        super(id, flags);
        this.factory = factory;
        this.data = data;
    }

    public Asn1AbstractChunk(Asn1AbstractChunkDataFactory<T> factory, Enumeration e) {
        super(e);
        this.factory = factory;
        this.data = factory.convert(e.nextElement());
    }

    public T getData() {
        return this.data;
    }

    @Override
    public ASN1Object dataToASN1Primitive() {
        return this.data;
    }
}
