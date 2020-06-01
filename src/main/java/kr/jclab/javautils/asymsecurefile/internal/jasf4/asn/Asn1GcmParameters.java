/*
 * AsymSecureFile
 * https://ablog.jc-lab.net/186
 *
 * This file origin is bcprov(bouncy castle).
 *
 *  This software may be modified and distributed under the terms
 *  of the Apache License 2.0.  See the LICENSE file for details.
 */

package kr.jclab.javautils.asymsecurefile.internal.jasf4.asn;

import org.bouncycastle.asn1.*;
import org.bouncycastle.util.Arrays;

/**
 * <a href="http://tools.ietf.org/html/rfc5084">RFC 5084</a>: GCMParameters object.
 * <p>
 * <pre>
 GCMParameters ::= SEQUENCE {
 aes-nonce        OCTET STRING, -- recommended size is 12 octets
 aes-ICVlen       AES-GCM-ICVlen DEFAULT 12 }
 * </pre>
 */
public class Asn1GcmParameters
        extends ASN1Object
{
    private byte[] nonce;
    private int icvLen;

    /**
     * Return an GCMParameters object from the given object.
     * <p>
     * Accepted inputs:
     * <ul>
     * <li> null &rarr; null
     * <li> {@link Asn1GcmParameters} object
     * <li> {@link org.bouncycastle.asn1.ASN1Sequence#getInstance(Object) ASN1Sequence} input formats with GCMParameters structure inside
     * </ul>
     *
     * @param obj the object we want converted.
     * @exception IllegalArgumentException if the object cannot be converted.
     */
    public static Asn1GcmParameters getInstance(
            Object  obj)
    {
        if (obj instanceof Asn1GcmParameters)
        {
            return (Asn1GcmParameters)obj;
        }
        else if (obj != null)
        {
            return new Asn1GcmParameters(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    private Asn1GcmParameters(
            ASN1Sequence seq)
    {
        this.nonce = ASN1OctetString.getInstance(seq.getObjectAt(0)).getOctets();

        if (seq.size() == 2)
        {
            this.icvLen = ASN1Integer.getInstance(seq.getObjectAt(1)).getValue().intValue();
        }
        else
        {
            this.icvLen = 12;
        }
    }

    public Asn1GcmParameters(
            byte[] nonce,
            int    icvLen)
    {
        this.nonce = Arrays.clone(nonce);
        this.icvLen = icvLen;
    }

    public byte[] getNonce()
    {
        return Arrays.clone(nonce);
    }

    public int getIcvLen()
    {
        return icvLen;
    }

    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector    v = new ASN1EncodableVector();

        v.add(new DEROctetString(nonce));

        v.add(new ASN1Integer(icvLen));

        return new DERSequence(v);
    }
}
