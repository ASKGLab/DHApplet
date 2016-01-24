/**
 * 3-Clause BSD License
 * Copyright (c) 2016, Thotheolh
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation and
 * /or other materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its contributors
 * may be used to endorse or promote products derived from this software without
 * specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
package dhapplet;

import javacard.framework.JCSystem;
import javacard.framework.TransactionException;
import javacard.security.AESKey;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.RSAPrivateKey;
import javacardx.crypto.Cipher;
import javacardx.framework.util.ArrayLogic;
import javacardx.framework.util.UtilException;

/**
 * Diffie-Hellman 2048 Group 14 specs from RFC-3526 as default.
 *
 * We assign the value P as the Prime and G as Generator. We use the RFC-3526
 * specific P and G as hard coded below but you may adjust the P and G carefully
 * according to your preference.
 *
 * The variable Y is assigned as the "public value" that both parties calculate
 * their modexp function and publicly exchange with each other. The S value is
 * the 2048 bit shared secret result.
 *
 * The maxLength should reflect the size of your DH key in terms of BYTES
 * instead of BITS as JavaCard only accept bytes. For a 2048 bit DH key, the
 * bytes are 256 of length.
 *
 * We assume that the card is Bob (Server) where Alice (Host) would initiate and
 * Bob would respond to Alice's initiation.
 *
 * For those seeking to adjust the DH key size o another key length, do kindly
 * adjust the P,G and maxLength accordingly. Due to reliance on JavaCard's RSA
 * engine for the DH crypto, the allowed key size is as follows below.
 *
 * JavaCard version 2.2.2 supported MODERN key size: 1024, 1280, 1536, 1984,
 * 2048.
 *
 * JavaCard version 3.0.4 supported MODERN key size: 1024, 1280, 1536, 1984,
 * 2048, 4096.
 *
 * You may need to query your card supplier on the JavaCard version and card's
 * native supported key sizes before using them.
 *
 * To know the key sizes in bytes, you divide the bit length by 8 to get the
 * byte length of each key type.
 *
 * To use the DH class, you need to do in the following steps:
 * 0.) Optional. Set the P and G to whatever values you like or use the default.
 *
 * 1.) Alice calls init() to derive Bob's "public key" parameter.
 *
 * 2.) Alice calls the getY() to retrieve Y which is Bob's "public key" to pass
 * to Alice.
 *
 * 3.) Alice calls the setY() to send over and overwrite Bob's "public key" with
 * Alice's "public key" to prepare for generating shared secret.
 *
 * 4.) Alice calls doFinal() to get Bob to derive the shared secret.
 *
 * @author Thotheolh
 */
public class DH {

    private RSAPrivateKey dhPriv;
    private Cipher dhCipher;

    private byte[] P = {
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xC9, (byte) 0x0F,
        (byte) 0xDA, (byte) 0xA2, (byte) 0x21, (byte) 0x68, (byte) 0xC2,
        (byte) 0x34, (byte) 0xC4, (byte) 0xC6, (byte) 0x62, (byte) 0x8B,
        (byte) 0x80, (byte) 0xDC, (byte) 0x1C, (byte) 0xD1, (byte) 0x29,
        (byte) 0x02, (byte) 0x4E, (byte) 0x08, (byte) 0x8A, (byte) 0x67,
        (byte) 0xCC, (byte) 0x74, (byte) 0x02, (byte) 0x0B, (byte) 0xBE,
        (byte) 0xA6, (byte) 0x3B, (byte) 0x13, (byte) 0x9B, (byte) 0x22,
        (byte) 0x51, (byte) 0x4A, (byte) 0x08, (byte) 0x79, (byte) 0x8E,
        (byte) 0x34, (byte) 0x04, (byte) 0xDD, (byte) 0xEF, (byte) 0x95,
        (byte) 0x19, (byte) 0xB3, (byte) 0xCD, (byte) 0x3A, (byte) 0x43,
        (byte) 0x1B, (byte) 0x30, (byte) 0x2B, (byte) 0x0A, (byte) 0x6D,
        (byte) 0xF2, (byte) 0x5F, (byte) 0x14, (byte) 0x37, (byte) 0x4F,
        (byte) 0xE1, (byte) 0x35, (byte) 0x6D, (byte) 0x6D, (byte) 0x51,
        (byte) 0xC2, (byte) 0x45, (byte) 0xE4, (byte) 0x85, (byte) 0xB5,
        (byte) 0x76, (byte) 0x62, (byte) 0x5E, (byte) 0x7E, (byte) 0xC6,
        (byte) 0xF4, (byte) 0x4C, (byte) 0x42, (byte) 0xE9, (byte) 0xA6,
        (byte) 0x37, (byte) 0xED, (byte) 0x6B, (byte) 0x0B, (byte) 0xFF,
        (byte) 0x5C, (byte) 0xB6, (byte) 0xF4, (byte) 0x06, (byte) 0xB7,
        (byte) 0xED, (byte) 0xEE, (byte) 0x38, (byte) 0x6B, (byte) 0xFB,
        (byte) 0x5A, (byte) 0x89, (byte) 0x9F, (byte) 0xA5, (byte) 0xAE,
        (byte) 0x9F, (byte) 0x24, (byte) 0x11, (byte) 0x7C, (byte) 0x4B,
        (byte) 0x1F, (byte) 0xE6, (byte) 0x49, (byte) 0x28, (byte) 0x66,
        (byte) 0x51, (byte) 0xEC, (byte) 0xE4, (byte) 0x5B, (byte) 0x3D,
        (byte) 0xC2, (byte) 0x00, (byte) 0x7C, (byte) 0xB8, (byte) 0xA1,
        (byte) 0x63, (byte) 0xBF, (byte) 0x05, (byte) 0x98, (byte) 0xDA,
        (byte) 0x48, (byte) 0x36, (byte) 0x1C, (byte) 0x55, (byte) 0xD3,
        (byte) 0x9A, (byte) 0x69, (byte) 0x16, (byte) 0x3F, (byte) 0xA8,
        (byte) 0xFD, (byte) 0x24, (byte) 0xCF, (byte) 0x5F, (byte) 0x83,
        (byte) 0x65, (byte) 0x5D, (byte) 0x23, (byte) 0xDC, (byte) 0xA3,
        (byte) 0xAD, (byte) 0x96, (byte) 0x1C, (byte) 0x62, (byte) 0xF3,
        (byte) 0x56, (byte) 0x20, (byte) 0x85, (byte) 0x52, (byte) 0xBB,
        (byte) 0x9E, (byte) 0xD5, (byte) 0x29, (byte) 0x07, (byte) 0x70,
        (byte) 0x96, (byte) 0x96, (byte) 0x6D, (byte) 0x67, (byte) 0x0C,
        (byte) 0x35, (byte) 0x4E, (byte) 0x4A, (byte) 0xBC, (byte) 0x98,
        (byte) 0x04, (byte) 0xF1, (byte) 0x74, (byte) 0x6C, (byte) 0x08,
        (byte) 0xCA, (byte) 0x18, (byte) 0x21, (byte) 0x7C, (byte) 0x32,
        (byte) 0x90, (byte) 0x5E, (byte) 0x46, (byte) 0x2E, (byte) 0x36,
        (byte) 0xCE, (byte) 0x3B, (byte) 0xE3, (byte) 0x9E, (byte) 0x77,
        (byte) 0x2C, (byte) 0x18, (byte) 0x0E, (byte) 0x86, (byte) 0x03,
        (byte) 0x9B, (byte) 0x27, (byte) 0x83, (byte) 0xA2, (byte) 0xEC,
        (byte) 0x07, (byte) 0xA2, (byte) 0x8F, (byte) 0xB5, (byte) 0xC5,
        (byte) 0x5D, (byte) 0xF0, (byte) 0x6F, (byte) 0x4C, (byte) 0x52,
        (byte) 0xC9, (byte) 0xDE, (byte) 0x2B, (byte) 0xCB, (byte) 0xF6,
        (byte) 0x95, (byte) 0x58, (byte) 0x17, (byte) 0x18, (byte) 0x39,
        (byte) 0x95, (byte) 0x49, (byte) 0x7C, (byte) 0xEA, (byte) 0x95,
        (byte) 0x6A, (byte) 0xE5, (byte) 0x15, (byte) 0xD2, (byte) 0x26,
        (byte) 0x18, (byte) 0x98, (byte) 0xFA, (byte) 0x05, (byte) 0x10,
        (byte) 0x15, (byte) 0x72, (byte) 0x8E, (byte) 0x5A, (byte) 0x8A,
        (byte) 0xAC, (byte) 0xAA, (byte) 0x68, (byte) 0xFF, (byte) 0xFF,
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        (byte) 0xFF
    };

    public static final short maxLength = 256;

    private byte[] G = {
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x02
    };

    private byte[] Y = JCSystem.makeTransientByteArray(maxLength, JCSystem.CLEAR_ON_RESET);
    private byte[] S = JCSystem.makeTransientByteArray(maxLength, JCSystem.CLEAR_ON_RESET);

    public DH() {
        // Creates a RSA private key instance as template for the DH private key
        dhPriv = (RSAPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PRIVATE_TRANSIENT_RESET, KeyBuilder.LENGTH_RSA_2048, false);

        // Creates an RSA cipher instance
        dhCipher = Cipher.getInstance(Cipher.ALG_RSA_NOPAD, false);
    }

    /**
     * Initializes the DH "public key" value of Y.
     */
    public void init() {
        // Create a keypair instance using an RSA keypair as template
        KeyPair dhKeyPair = new KeyPair(KeyPair.ALG_RSA, (short) dhPriv.getSize());

        // Gen DH private key
        dhKeyPair.genKeyPair();
        dhPriv = (RSAPrivateKey) dhKeyPair.getPrivate();

        // Load DH's P as RSA's M
        dhPriv.setModulus(P, (short) 0, maxLength);

        // Set private key into cipher
        dhCipher.init(dhPriv, Cipher.MODE_ENCRYPT);

        // Execute Y = G^bobPrivKey mod P via RSA's encrypt
        dhCipher.doFinal(G, (short) 0, maxLength, Y, (short) 0);
    }

    /**
     * Get G value.
     *
     * @return
     */
    public void getG(byte[] output, short offset) {
        ArrayLogic.arrayCopyRepackNonAtomic(G, (short) 0, maxLength, output, offset);
    }

    /**
     * Get P value.
     *
     * @return
     */
    public void getP(byte[] output, short offset) {
        ArrayLogic.arrayCopyRepackNonAtomic(P, (short) 0, maxLength, output, offset);
    }

    /**
     * Get Y value.
     *
     * @return
     */
    public void getY(byte[] output, short offset) {
    }

    /**
     * Set Y value.
     *
     * @param data
     * @param offset
     * @param length
     * @param targetOffset
     * @throws ArrayIndexOutOfBoundsException
     * @throws NullPointerException
     * @throws TransactionException
     * @throws UtilException
     */
    public void setY(byte[] data, short offset, short length, short yOffset) throws ArrayIndexOutOfBoundsException, NullPointerException, TransactionException, UtilException {
        ArrayLogic.arrayCopyRepack(data, offset, length, Y, yOffset);
    }

    /**
     * Set P value.
     *
     * @param data
     * @param offset
     * @param length
     * @param targetOffset
     * @throws ArrayIndexOutOfBoundsException
     * @throws NullPointerException
     * @throws TransactionException
     * @throws UtilException
     */
    public void setP(byte[] data, short offset, short length, short pOffset) throws ArrayIndexOutOfBoundsException, NullPointerException, TransactionException, UtilException {
        ArrayLogic.arrayCopyRepack(data, offset, length, P, pOffset);
    }

    /**
     * Set G value.
     *
     * @param data
     * @param offset
     * @param length
     * @param targetOffset
     * @throws ArrayIndexOutOfBoundsException
     * @throws NullPointerException
     * @throws TransactionException
     * @throws UtilException
     */
    public void setG(byte[] data, short offset, short length, short gOffset) throws ArrayIndexOutOfBoundsException, NullPointerException, TransactionException, UtilException {
        ArrayLogic.arrayCopyRepack(data, offset, length, G, gOffset);
    }

    /**
     * Destroys DH private key.
     */
    public void clearKey() {
        dhPriv.clearKey();
    }

    /**
     * Executes the DH function of S = Y^a mod p which is essentially the modexp
     * that is reusable from the modexp (encrypt/decrypt) of RSA. Y is thus
     * taken as a message in terms of RSA.
     *
     * Both Y and S are zeroized after this operation to prevent leaking of
     * security parameters but you might choose to retain the parameters by
     * removing the zeroize function at your own risk.
     *
     * The first 16 bytes (128 bits) of the shared secret is used for a 128 bits
     * AES encryption key. You may derive your HMAC key from S but for
     * simplicity of the demo, we will only encrypt.
     *
     * @param Y
     */
    public void doFinal(AESKey encKey) {
        // Set private key into cipher
        dhCipher.init(dhPriv, Cipher.MODE_ENCRYPT);

        // Execute S = Y^a mod p via RSA's encrypt
        dhCipher.doFinal(Y, (short) 0, maxLength, S, (short) 0);

        // Set session Encryption key
        encKey.setKey(S, (short) 0);

        // Clear DH Private Key
        dhPriv.clearKey();

        // Zeroize temporary S bytes.
        Utils.zeroize(S);

        // Zeroize temporary Y bytes.
        Utils.zeroize(Y);
    }
}
