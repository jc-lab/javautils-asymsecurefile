/*
 * AsymSecureFile
 * https://ablog.jc-lab.net/186
 *
 *  This software may be modified and distributed under the terms
 *  of the Apache License 2.0.  See the LICENSE file for details.
 */

package kr.jclab.javautils.asymsecurefile;

import java.io.IOException;

public class NotSupportAlgorithmException extends IOException {
    public NotSupportAlgorithmException() {
        super();
    }

    public NotSupportAlgorithmException(String message) {
        super(message);
    }

    public NotSupportAlgorithmException(String message, Throwable cause) {
        super(message, cause);
    }

    public NotSupportAlgorithmException(Throwable cause) {
        super(cause);
    }
}
