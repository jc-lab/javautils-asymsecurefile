/*
 * AsymSecureFile
 * https://ablog.jc-lab.net/186
 *
 *  This software may be modified and distributed under the terms
 *  of the Apache License 2.0.  See the LICENSE file for details.
 */

package kr.jclab.javautils.asymsecurefile;

public class UserChunk extends Chunk {
    public UserChunk(byte primaryType, short userType, short dataSize, byte[] data) {
        super((byte)(primaryType | 0x80), userType, dataSize, data);
    }

    public short getUserCode() {
        return userCode;
    }
}
