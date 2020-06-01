/*
 * AsymSecureFile
 * https://ablog.jc-lab.net/186
 *
 *  This software may be modified and distributed under the terms
 *  of the Apache License 2.0.  See the LICENSE file for details.
 */

package kr.jclab.javautils.asymsecurefile.internal.jasf4.asn;

import kr.jclab.javautils.asymsecurefile.internal.AsymmetricAlgorithmType;
import kr.jclab.javautils.asymsecurefile.internal.jasf4.ChunkResolver;
import org.bouncycastle.asn1.*;

import java.util.Enumeration;

public class Asn1DefaultHeaderChunk extends Asn1ObjectChunkBase {
	public static final ChunkId CHUNK_ID = ChunkId.DefaultHeader;

	private final int subVersion;
	private final AsymmetricAlgorithmType asymmetricAlgorithmType;
	private final ASN1ObjectIdentifier chunkCryptoAlgorithm;
	private final ASN1ObjectIdentifier dataCryptoAlgorithm;
	private final ASN1ObjectIdentifier fingerprintAlgorithm;
	private final ASN1OctetString authKeyCryptionIv;

	@ChunkInitializer
	public static void init() {
		ChunkResolver.addChunkClass(CHUNK_ID, Asn1DefaultHeaderChunk.class, Asn1DefaultHeaderChunk::new);
	}

	public static Asn1DefaultHeaderChunk getInstance(
			ASN1TaggedObject obj,
			boolean          explicit)
	{
		return getInstance(ASN1Sequence.getInstance(obj, explicit));
	}

	public static Asn1DefaultHeaderChunk getInstance(
			Object obj)
	{
		if (obj instanceof Asn1DefaultHeaderChunk)
		{
			return (Asn1DefaultHeaderChunk)obj;
		}

		if (obj != null)
		{
			return new Asn1DefaultHeaderChunk(ASN1Sequence.getInstance(obj).getObjects());
		}

		return null;
	}

	public Asn1DefaultHeaderChunk(int subVersion, AsymmetricAlgorithmType asymmetricAlgorithmType, ASN1ObjectIdentifier chunkCryptoAlgorithm, ASN1ObjectIdentifier dataCryptoAlgorithm, ASN1ObjectIdentifier fingerprintAlgorithm, byte[] authKeyCryptionIv) {
		super(CHUNK_ID, new Asn1ChunkFlags());
		this.subVersion = subVersion;
		this.asymmetricAlgorithmType = asymmetricAlgorithmType;
		this.chunkCryptoAlgorithm = chunkCryptoAlgorithm;
		this.dataCryptoAlgorithm = dataCryptoAlgorithm;
		this.fingerprintAlgorithm = fingerprintAlgorithm;
		this.authKeyCryptionIv = new DEROctetString(authKeyCryptionIv);
	}

	private Asn1DefaultHeaderChunk(Enumeration e) {
		super(e);
		ASN1Sequence sequence = ASN1Sequence.getInstance(e.nextElement());
		this.subVersion = ASN1Integer.getInstance(sequence.getObjectAt(0)).getValue().intValue();
		this.asymmetricAlgorithmType = AsymmetricAlgorithmType.fromValue(ASN1Integer.getInstance(sequence.getObjectAt(1)).getValue().intValue());
		this.chunkCryptoAlgorithm = ASN1ObjectIdentifier.getInstance(sequence.getObjectAt(2));
		this.dataCryptoAlgorithm = ASN1ObjectIdentifier.getInstance(sequence.getObjectAt(3));
		this.fingerprintAlgorithm = ASN1ObjectIdentifier.getInstance(sequence.getObjectAt(4));
		this.authKeyCryptionIv = ASN1OctetString.getInstance(sequence.getObjectAt(5));
	}

	@Override
	public ASN1Object dataToASN1Primitive() {
		ASN1EncodableVector v = new ASN1EncodableVector();

		v.add(new ASN1Integer(this.subVersion));
		v.add(new ASN1Integer(this.asymmetricAlgorithmType.getValue()));
		v.add(this.chunkCryptoAlgorithm);
		v.add(this.dataCryptoAlgorithm);
		v.add(this.fingerprintAlgorithm);
		v.add(this.authKeyCryptionIv);

		return new DERSequence(v);
	}

	public int getSubVersion() {
		return subVersion;
	}

	public AsymmetricAlgorithmType getAsymmetricAlgorithmType() {
		return asymmetricAlgorithmType;
	}

	public ASN1ObjectIdentifier getChunkCryptoAlgorithm() {
		return chunkCryptoAlgorithm;
	}

	public ASN1ObjectIdentifier getDataCryptoAlgorithm() {
		return dataCryptoAlgorithm;
	}

	public ASN1ObjectIdentifier getFingerprintAlgorithm() {
		return fingerprintAlgorithm;
	}

	public ASN1OctetString getAuthKeyCryptionIv() {
		return authKeyCryptionIv;
	}
}

