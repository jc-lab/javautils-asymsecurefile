/*
 * AsymSecureFile
 * https://ablog.jc-lab.net/186
 *
 *  This software may be modified and distributed under the terms
 *  of the Apache License 2.0.  See the LICENSE file for details.
 */

package kr.jclab.javautils.asymsecurefile.internal.jasf4.asn;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;

public class Asn1ChunkFlags extends ASN1Object {
    private int value = 0;

    public Asn1ChunkFlags(Asn1ChunkFlags value) {
        this.value = value.value;
    }

    public Asn1ChunkFlags() {
        this(0);
    }
    public Asn1ChunkFlags(int value) {
        this.value = value;
    }

    public static Asn1ChunkFlags getInstance(int value) {
        return new Asn1ChunkFlags(value);
    }

    public static Asn1ChunkFlags getInstance(Object object) {
        ASN1Integer asnObject = ASN1Integer.getInstance(object);
        return new Asn1ChunkFlags(asnObject.getValue().intValue());
    }

    public int getValue() {
        return value;
    }

    @Override
    public ASN1Primitive toASN1Primitive() {
        return new ASN1Integer(this.value);
    }

    public void encryptWithAuthKey() {
        this.encryptWithAuthKey(true);
    }

    public void encryptWithAuthKey(boolean v) {
        if (v) {
            this.value |= 0x0001;
        }else{
            this.value &= ~0x0001;
        }
    }

    public boolean isEncryptWithAuthKey() {
        return (this.value & 0x0001) != 0;
    }
}
