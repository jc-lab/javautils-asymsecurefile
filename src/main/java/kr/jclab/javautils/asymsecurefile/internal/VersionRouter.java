/*
 * AsymSecureFile
 * https://ablog.jc-lab.net/186
 *
 *  This software may be modified and distributed under the terms
 *  of the Apache License 2.0.  See the LICENSE file for details.
 */

package kr.jclab.javautils.asymsecurefile.internal;

import kr.jclab.javautils.asymsecurefile.AsymSecureFileVersion;
import kr.jclab.javautils.asymsecurefile.NotSupportVersionException;
import kr.jclab.javautils.asymsecurefile.internal.jasf3.Jasf3InputStreamDelegate;
import kr.jclab.javautils.asymsecurefile.internal.jasf3.Jasf3OutputStreamDelegate;
import kr.jclab.javautils.asymsecurefile.internal.jasf4.Jasf4InputStreamDelegate;
import kr.jclab.javautils.asymsecurefile.internal.jasf4.Jasf4OutputStreamDelegate;
import kr.jclab.javautils.asymsecurefile.internal.signedsecurefile.SignedSecureFileInputStreamDelegate;

import java.util.HashMap;

public class VersionRouter {
    private static final HashMap<Integer, Class<? extends InputStreamDelegate>> READER_MAP = new HashMap<>();
    private static final HashMap<Integer, Class<? extends OutputStreamDelegate>> WRITER_MAP = new HashMap<>();

    static {
        READER_MAP.put(AsymSecureFileVersion.V1.getVersion(), SignedSecureFileInputStreamDelegate.class);
        READER_MAP.put(AsymSecureFileVersion.V2.getVersion(), SignedSecureFileInputStreamDelegate.class);
        READER_MAP.put(AsymSecureFileVersion.JASF_3.getVersion(), Jasf3InputStreamDelegate.class);
        READER_MAP.put(AsymSecureFileVersion.JASF_4_1.getVersion(), Jasf4InputStreamDelegate.class);
        WRITER_MAP.put(AsymSecureFileVersion.JASF_3.getVersion(), Jasf3OutputStreamDelegate.class);
        WRITER_MAP.put(AsymSecureFileVersion.JASF_4_1.getVersion(), Jasf4OutputStreamDelegate.class);
    }

    public static Class<? extends InputStreamDelegate> findReaderDelegate(int version) throws NotSupportVersionException {
        Class<? extends InputStreamDelegate> delegateClass = READER_MAP.get(version);
        if(delegateClass == null) {
            throw new NotSupportVersionException("Not Support Reader: version=" + version);
        }
        return delegateClass;
    }

    public static Class<? extends OutputStreamDelegate> findWriterDelegate(int version) throws NotSupportVersionException {
        Class<? extends OutputStreamDelegate> delegateClass = WRITER_MAP.get(version);
        if (delegateClass == null) {
            throw new NotSupportVersionException("Not Support Writer: version=" + version);
        }
        return delegateClass;
    }

    public static Class<? extends InputStreamDelegate> findReaderDelegate(AsymSecureFileVersion version) throws NotSupportVersionException {
        return findReaderDelegate(version.getVersion());
    }

    public static Class<? extends OutputStreamDelegate> findWriterDelegate(AsymSecureFileVersion version) throws NotSupportVersionException {
        return findWriterDelegate(version.getVersion());
    }

    public static Class<? extends OutputStreamDelegate> getWriterDelegate() {
        return Jasf4OutputStreamDelegate.class;
    }
}
