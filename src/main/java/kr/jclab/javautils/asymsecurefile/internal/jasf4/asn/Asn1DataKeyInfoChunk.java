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

import java.io.IOException;
import java.util.Arrays;
import java.util.Enumeration;

/**
 * CONSTRUCTED
 */
public class Asn1DataKeyInfoChunk extends Asn1ObjectChunkBase {
	public static final ChunkId CHUNK_ID = ChunkId.DataKeyInfo;
	private static final byte[] VALIDED_SIGNATURE = new byte[] { (byte)0x01, (byte)0xcf, (byte)0xcb, (byte)0xff};

	private final ASN1OctetString signature;
	private final ASN1OctetString dataKey;
	private final ASN1OctetString macKey;

	@ChunkInitializer
	public static void init() {
		ChunkResolver.addChunkClass(CHUNK_ID, Asn1DataKeyInfoChunk.class, Asn1DataKeyInfoChunk::new);
	}

	public static Asn1DataKeyInfoChunk getInstance(
			ASN1TaggedObject obj,
			boolean          explicit)
	{
		return getInstance(ASN1Sequence.getInstance(obj, explicit));
	}

	public static Asn1DataKeyInfoChunk getInstance(
			Object obj)
	{
		if (obj instanceof Asn1DataKeyInfoChunk)
		{
			return (Asn1DataKeyInfoChunk)obj;
		}

		if (obj != null)
		{
			return new Asn1DataKeyInfoChunk(ASN1Sequence.getInstance(obj).getObjects());
		}

		return null;
	}

	public static Asn1DataKeyInfoChunk fromDataPart(byte[] encoded) throws IOException {
		ASN1InputStream asn1InputStream = new ASN1InputStream(encoded);
		ASN1Sequence sequence = ASN1Sequence.getInstance(asn1InputStream.readObject());
		ASN1OctetString signature = ASN1OctetString.getInstance(sequence.getObjectAt(0));
		ASN1OctetString dataKey = ASN1OctetString.getInstance(sequence.getObjectAt(1));
		ASN1OctetString macKey = ASN1OctetString.getInstance(sequence.getObjectAt(2));
		return new Asn1DataKeyInfoChunk(
				signature,
				dataKey,
				macKey
		);
	}

	private static Asn1ChunkFlags defaultFlags() {
		Asn1ChunkFlags flags = new Asn1ChunkFlags();
		flags.encryptWithAuthKey(true);
		return flags;
	}

	public Asn1DataKeyInfoChunk(byte[] dataKey, byte[] macKey) {
		super(CHUNK_ID, defaultFlags());
		this.signature = new DEROctetString(VALIDED_SIGNATURE);
		this.dataKey = new DEROctetString(dataKey);
		this.macKey = new DEROctetString(macKey);
	}

	private Asn1DataKeyInfoChunk(ASN1OctetString signature, ASN1OctetString dataKey, ASN1OctetString macKey) {
		super(CHUNK_ID, defaultFlags());
		this.signature = signature;
		this.dataKey = dataKey;
		this.macKey = macKey;
	}

	private Asn1DataKeyInfoChunk(Enumeration e) {
		super(e);
		ASN1Sequence sequence = ASN1Sequence.getInstance(e.nextElement());
		this.signature = ASN1OctetString.getInstance(sequence.getObjectAt(0));
		this.dataKey = ASN1OctetString.getInstance(sequence.getObjectAt(1));
		this.macKey = ASN1OctetString.getInstance(sequence.getObjectAt(2));
	}

	public boolean validate() {
		return Arrays.equals(VALIDED_SIGNATURE, this.signature.getOctets());
	}

	@Override
	public ASN1Object dataToASN1Primitive() {
		ASN1EncodableVector v = new ASN1EncodableVector();

		v.add(this.signature);
		v.add(this.dataKey);
		v.add(this.macKey);

		return new DERSequence(v);
	}

	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		appendAsString(sb, 0);
		return sb.toString();
	}

	public void appendAsString(StringBuilder sb, int indentLevel) {

		sb.append("{");
		sb.append("\n");
		for (int i = 0; i < indentLevel + 1; i++) {
			sb.append("\t");
		}
		if (signature != null) {
			sb.append("signature: ").append(signature);
		}
		else {
			sb.append("signature: <empty-required-field>");
		}
		
		sb.append(",\n");
		for (int i = 0; i < indentLevel + 1; i++) {
			sb.append("\t");
		}
		if (dataKey != null) {
			sb.append("dataKey: ").append(dataKey);
		}
		else {
			sb.append("dataKey: <empty-required-field>");
		}
		
		sb.append(",\n");
		for (int i = 0; i < indentLevel + 1; i++) {
			sb.append("\t");
		}
		if (macKey != null) {
			sb.append("macKey: ").append(macKey);
		}
		else {
			sb.append("macKey: <empty-required-field>");
		}
		
		sb.append("\n");
		for (int i = 0; i < indentLevel; i++) {
			sb.append("\t");
		}
		sb.append("}");
	}

	public byte[] getDataKey() {
		return dataKey.getOctets();
	}

	public byte[] getMacKey() {
		return macKey.getOctets();
	}
}

