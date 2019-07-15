/*
 * AsymSecureFile
 * https://ablog.jc-lab.net/186
 *
 *  This software may be modified and distributed under the terms
 *  of the Apache License 2.0.  See the LICENSE file for details.
 */

package kr.jclab.javautils.asymsecurefile.internal;

import kr.jclab.javautils.asymsecurefile.NotSupportVersion;
import kr.jclab.javautils.asymsecurefile.internal.jasf3.Jasf3InputStreamDelegate;
import kr.jclab.javautils.asymsecurefile.internal.jasf3.Jasf3OutputStreamDelegate;
import kr.jclab.javautils.asymsecurefile.internal.signedsecurefile.SignedSecureFileInputStreamDelegate;

import java.util.HashMap;

public class VersionRouter {
    private static final HashMap<Byte, Class<? extends InputStreamDelegate>> READER_MAP = new HashMap<>();
    private static final HashMap<Byte, Class<? extends OutputStreamDelegate>> WRITER_MAP = new HashMap<>();

    static {
        READER_MAP.put((byte)1, SignedSecureFileInputStreamDelegate.class);
        READER_MAP.put((byte)2, SignedSecureFileInputStreamDelegate.class);
        READER_MAP.put((byte)3, Jasf3InputStreamDelegate.class);
        WRITER_MAP.put((byte)3, Jasf3OutputStreamDelegate.class);
    }

    public static Class<? extends InputStreamDelegate> findReaderDelegate(byte version) throws NotSupportVersion {
        Class<? extends InputStreamDelegate> delegateClass = READER_MAP.get(version);
        if(delegateClass == null) {
            throw new NotSupportVersion("Not Support Reader: version=" + version);
        }
        return delegateClass;
    }

    public static Class<? extends OutputStreamDelegate> findWriterDelegate(byte version) throws NotSupportVersion {
        if(version != (byte)0xff) {
            Class<? extends OutputStreamDelegate> delegateClass = WRITER_MAP.get(version);
            if (delegateClass == null) {
                throw new NotSupportVersion("Not Support Writer: version=" + version);
            }
            return delegateClass;
        }
        return Jasf3OutputStreamDelegate.class;
    }

    public static Class<? extends OutputStreamDelegate> getWriterDelegate() {
        return Jasf3OutputStreamDelegate.class;
    }
}
