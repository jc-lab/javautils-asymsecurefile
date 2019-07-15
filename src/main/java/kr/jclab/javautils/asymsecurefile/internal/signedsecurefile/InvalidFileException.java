/*
 * AsymSecureFile
 * https://ablog.jc-lab.net/186
 *
 *  This software may be modified and distributed under the terms
 *  of the Apache License 2.0.  See the LICENSE file for details.
 */

package kr.jclab.javautils.asymsecurefile.internal.signedsecurefile;

import java.io.IOException;

public class InvalidFileException extends IOException {
    public InvalidFileException() {
        super("Invalid file");
    }

    public InvalidFileException(String message) {
        super(message);
    }
}
