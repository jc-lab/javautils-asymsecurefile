package kr.jclab.javautils.asymsecurefile.internal.utils;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA224Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;

import java.util.*;
import java.util.function.Supplier;

public class HashAlgorithms {
    public static class AlgorithmEntry {
        private final String name;
        private final ASN1ObjectIdentifier oid;
        private final ASN1ObjectIdentifier hmacOid;
        private final int digestSize;
        private final Supplier<Digest> bcDigestSupplier;

        public AlgorithmEntry(String name, ASN1ObjectIdentifier oid, ASN1ObjectIdentifier hmacOid, Supplier<Digest> bcDigestSupplier) {
            this.name = name;
            this.oid = oid;
            this.hmacOid = hmacOid;
            this.digestSize = bcDigestSupplier.get().getDigestSize();
            this.bcDigestSupplier = bcDigestSupplier;
        }

        public String getName() {
            return this.name;
        }

        public ASN1ObjectIdentifier getOid() {
            return this.oid;
        }

        public ASN1ObjectIdentifier getHmacOid() {
            return hmacOid;
        }

        public int getDigestSize() {
            return this.digestSize;
        }

        public Supplier<Digest> getBcDigestSupplier() {
            return this.bcDigestSupplier;
        }

        public Digest createDigest() {
            return this.bcDigestSupplier.get();
        }
    }

    public static AlgorithmEntry findByName(String name) {
        return SingletoneHolder.NAME_MAP.get(name);
    }

    public static AlgorithmEntry findByOid(String oid) {
        return SingletoneHolder.OID_MAP.get(oid);
    }

    public static AlgorithmEntry findByOid(ASN1ObjectIdentifier oid) {
        return SingletoneHolder.OID_MAP.get(oid.getId());
    }

    public static AlgorithmEntry findByHmacOid(String oid) {
        return SingletoneHolder.HMAC_OID_MAP.get(oid);
    }

    public static AlgorithmEntry findByHmacOid(ASN1ObjectIdentifier oid) {
        return SingletoneHolder.HMAC_OID_MAP.get(oid.getId());
    }

    private static class SingletoneHolder {
        private static Map<String, AlgorithmEntry> NAME_MAP;
        private static Map<String, AlgorithmEntry> OID_MAP;
        private static Map<String, AlgorithmEntry> HMAC_OID_MAP;

        static {
            final List<AlgorithmEntry> entries = Arrays.asList(
                    new AlgorithmEntry("sha256", NISTObjectIdentifiers.id_sha256, PKCSObjectIdentifiers.id_hmacWithSHA256, SHA256Digest::new),
                    new AlgorithmEntry("sha384", NISTObjectIdentifiers.id_sha384, PKCSObjectIdentifiers.id_hmacWithSHA384, SHA384Digest::new),
                    new AlgorithmEntry("sha512", NISTObjectIdentifiers.id_sha512, PKCSObjectIdentifiers.id_hmacWithSHA512, SHA512Digest::new),
                    new AlgorithmEntry("sha224", NISTObjectIdentifiers.id_sha224, PKCSObjectIdentifiers.id_hmacWithSHA224, SHA224Digest::new)
            );
            NAME_MAP = Collections.unmodifiableMap(new HashMap<String, AlgorithmEntry>() {{
                for(AlgorithmEntry entry : entries) {
                    put(entry.getName(), entry);
                }
            }});
            OID_MAP = Collections.unmodifiableMap(new HashMap<String, AlgorithmEntry>() {{
                for(AlgorithmEntry entry : entries) {
                    put(entry.getOid().toString(), entry);
                }
            }});
            HMAC_OID_MAP = Collections.unmodifiableMap(new HashMap<String, AlgorithmEntry>() {{
                for(AlgorithmEntry entry : entries) {
                    put(entry.getHmacOid().toString(), entry);
                }
            }});
        }
    }
}
