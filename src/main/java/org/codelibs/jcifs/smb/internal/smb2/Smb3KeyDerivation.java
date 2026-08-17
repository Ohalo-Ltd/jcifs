/*
 * © 2017 AgNO3 Gmbh & Co. KG
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */
package org.codelibs.jcifs.smb.internal.smb2;

import java.nio.charset.StandardCharsets;

import org.bouncycastle.crypto.DerivationParameters;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.KDFCounterBytesGenerator;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KDFCounterParameters;

/**
 * SMB3 SP800-108 Counter Mode Key Derivation
 *
 * @author mbechler
 *
 */
public final class Smb3KeyDerivation {

    private static final byte[] SIGNCONTEXT_300 = toCBytes("SmbSign");
    private static final byte[] SIGNLABEL_300 = toCBytes("SMB2AESCMAC");
    private static final byte[] SIGNLABEL_311 = toCBytes("SMBSigningKey");

    private static final byte[] APPCONTEXT_300 = toCBytes("SmbRpc");
    private static final byte[] APPLABEL_300 = toCBytes("SMB2APP");
    private static final byte[] APPLABEL_311 = toCBytes("SMBAppKey");

    private static final byte[] ENCCONTEXT_300 = toCBytes("ServerIn "); // there really is a space there
    private static final byte[] ENCLABEL_300 = toCBytes("SMB2AESCCM");
    private static final byte[] ENCLABEL_311 = toCBytes("SMBC2SCipherKey");

    private static final byte[] DECCONTEXT_300 = toCBytes("ServerOut");
    private static final byte[] DECLABEL_300 = toCBytes("SMB2AESCCM");
    private static final byte[] DECLABEL_311 = toCBytes("SMBS2CCipherKey");

    /**
     *
     */
    private Smb3KeyDerivation() {
    }

    /**
     * Derives the SMB3 signing key from the session key using the appropriate KDF for the dialect.
     *
     * @param dialect the SMB dialect version
     * @param sessionKey the base session key
     * @param preauthIntegrity the pre-authentication integrity hash (for SMB 3.1.1) or null
     * @return derived signing key
     */
    public static byte[] deriveSigningKey(final int dialect, final byte[] sessionKey, final byte[] preauthIntegrity) {
        return derive(sessionKey, dialect == Smb2Constants.SMB2_DIALECT_0311 ? SIGNLABEL_311 : SIGNLABEL_300,
                dialect == Smb2Constants.SMB2_DIALECT_0311 ? preauthIntegrity : SIGNCONTEXT_300);
    }

    /**
     * Derives the SMB3 application key from the session key using the appropriate KDF for the dialect.
     *
     * @param dialect the SMB dialect version
     * @param sessionKey the base session key
     * @param preauthIntegrity the pre-authentication integrity hash (for SMB 3.1.1) or null
     * @return derived application key
     */
    public static byte[] dervieApplicationKey(final int dialect, final byte[] sessionKey, final byte[] preauthIntegrity) {
        return derive(sessionKey, dialect == Smb2Constants.SMB2_DIALECT_0311 ? APPLABEL_311 : APPLABEL_300,
                dialect == Smb2Constants.SMB2_DIALECT_0311 ? preauthIntegrity : APPCONTEXT_300);
    }

    /**
     * Derives the SMB3 encryption key from the session key using the appropriate KDF for the dialect.
     *
     * @param dialect the SMB dialect version
     * @param sessionKey the base session key
     * @param preauthIntegrity the pre-authentication integrity hash (for SMB 3.1.1) or null
     * @return derived 16-byte encryption key
     */
    public static byte[] deriveEncryptionKey(final int dialect, final byte[] sessionKey, final byte[] preauthIntegrity) {
        return deriveEncryptionKey(dialect, sessionKey, preauthIntegrity, 16);
    }

    /**
     * Derives the SMB3 encryption key of the given length from the session key.
     *
     * @param dialect the SMB dialect version
     * @param sessionKey the base session key
     * @param preauthIntegrity the pre-authentication integrity hash (for SMB 3.1.1) or null
     * @param keyLength the cipher's key length in bytes (16 for AES-128, 32 for AES-256)
     * @return derived encryption key
     */
    public static byte[] deriveEncryptionKey(final int dialect, final byte[] sessionKey, final byte[] preauthIntegrity,
            final int keyLength) {
        return derive(sessionKey, dialect == Smb2Constants.SMB2_DIALECT_0311 ? ENCLABEL_311 : ENCLABEL_300,
                dialect == Smb2Constants.SMB2_DIALECT_0311 ? preauthIntegrity : ENCCONTEXT_300, keyLength);
    }

    /**
     * Derives the SMB3 decryption key from the session key using the appropriate KDF for the dialect.
     *
     * @param dialect the SMB dialect version
     * @param sessionKey the base session key
     * @param preauthIntegrity the pre-authentication integrity hash (for SMB 3.1.1) or null
     * @return derived 16-byte decryption key
     */
    public static byte[] deriveDecryptionKey(final int dialect, final byte[] sessionKey, final byte[] preauthIntegrity) {
        return deriveDecryptionKey(dialect, sessionKey, preauthIntegrity, 16);
    }

    /**
     * Derives the SMB3 decryption key of the given length from the session key.
     *
     * @param dialect the SMB dialect version
     * @param sessionKey the base session key
     * @param preauthIntegrity the pre-authentication integrity hash (for SMB 3.1.1) or null
     * @param keyLength the cipher's key length in bytes (16 for AES-128, 32 for AES-256)
     * @return derived decryption key
     */
    public static byte[] deriveDecryptionKey(final int dialect, final byte[] sessionKey, final byte[] preauthIntegrity,
            final int keyLength) {
        return derive(sessionKey, dialect == Smb2Constants.SMB2_DIALECT_0311 ? DECLABEL_311 : DECLABEL_300,
                dialect == Smb2Constants.SMB2_DIALECT_0311 ? preauthIntegrity : DECCONTEXT_300, keyLength);

    }

    private static byte[] derive(final byte[] sessionKey, final byte[] label, final byte[] context) {
        return derive(sessionKey, label, context, 16);
    }

    /**
     * @param sessionKey
     * @param label
     * @param context
     * @param keyLength output key length in bytes
     */
    private static byte[] derive(final byte[] sessionKey, final byte[] label, final byte[] context, final int keyLength) {
        final KDFCounterBytesGenerator gen = new KDFCounterBytesGenerator(new HMac(new SHA256Digest()));

        final int r = 32;
        final byte[] suffix = new byte[label.length + context.length + 5];
        // per bouncycastle
        // <li>1: K(i) := PRF( KI, [i]_2 || Label || 0x00 || Context || [L]_2 ) with the counter at the very beginning
        // of the fixedInputData (The default implementation has this format)</li>
        // with the parameters
        // <li>1. KDFCounterParameters(ki, null, "Label || 0x00 || Context || [L]_2]", 8);

        // all fixed inputs go into the suffix:
        // + label
        System.arraycopy(label, 0, suffix, 0, label.length);
        // + 1 byte 0x00
        // + context
        System.arraycopy(context, 0, suffix, label.length + 1, context.length);
        // + 4 byte big endian encoding of L, the output length in bits
        // (128 encodes as 00 00 00 80, 256 as 00 00 01 00)
        final int lBits = keyLength * 8;
        suffix[suffix.length - 2] = (byte) (lBits >> 8 & 0xFF);
        suffix[suffix.length - 1] = (byte) (lBits & 0xFF);

        final DerivationParameters param = new KDFCounterParameters(sessionKey, null /* prefix */, suffix /* suffix */, r /* r */);
        gen.init(param);

        final byte[] derived = new byte[keyLength];
        gen.generateBytes(derived, 0, keyLength);
        return derived;
    }

    /**
     * @param string
     * @return null terminated ASCII bytes
     */
    private static byte[] toCBytes(final String string) {
        final byte[] data = new byte[string.length() + 1];
        System.arraycopy(string.getBytes(StandardCharsets.US_ASCII), 0, data, 0, string.length());
        return data;
    }

}
