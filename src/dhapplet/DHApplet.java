/*
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

import javacard.framework.*;
import javacard.security.AESKey;
import javacard.security.KeyBuilder;
import javacardx.crypto.Cipher;
import javacardx.framework.util.ArrayLogic;

/**
 * A Diffie-Hellman sample applet that uses the card's RNG to generate a 2048
 * bit (256 bytes) DH private key and then transact over a plain channel to
 * establish a 2048 but shared secret which is used to derive subsequent
 * symmetric keys.
 *
 * The lack of a non-ECC Diffie Hellman implementation makes it tricky to
 * implement a DH channel in JavaCard.
 *
 * Due to DH and RSA both share a common modexp function, the RSA crypto engine
 * of a smart card can be used to perform the modexp that DH also relies on
 * thus solving the issue of not needing to creaete your DH from scratch but
 * simply leveraging the RSA engine in a JavaCard to do the work for you while
 * you lightly wrap your DH functions over the RSA functions.
 *
 * You may use a 4096 bits (512 bytes) DH key if your card supports the version
 * 3.0.4 of JavaCard and your card supplier indicates that the card has a
 * 4096 bit RSA support.
 *
 * @author Thotheolh
 */
public class DHApplet extends Applet {

    // Flags
    public final static byte CLA = (byte) 0xB0;
    public final static byte INS_INIT = (byte) 0x10;
    public final static byte INS_GET = (byte) 0x11;
    public final static byte INS_SET = (byte) 0x12;
    public final static byte INS_FINAL = (byte) 0x1F;
    public final static byte INS_TEST = (byte) 0x20;
    public final static byte P1_Y = (byte) 0x01;
    public final static byte P1_P = (byte) 0x02;
    public final static byte P1_G = (byte) 0x03;
    public final static byte P1_INIT_WITH_PRIVKEY = (byte) 0x1F;
    public final static byte BLANK = (byte) 0x00;

    //Variables
    public DH dh;
    private final AESKey encKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES_TRANSIENT_RESET, KeyBuilder.LENGTH_AES_128, false);
    public final byte[] buffer = JCSystem.makeTransientByteArray(DH.maxLength, JCSystem.CLEAR_ON_RESET);
    private final Cipher aesCipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_ECB_NOPAD, false);
    public final byte[] reply = {(byte) 0x48, (byte) 0x65, (byte) 0x6c, (byte) 0x6c,
        (byte) 0x6f, (byte) 0x20, (byte) 0x4a, (byte) 0x61, (byte) 0x76, (byte) 0x61,
        (byte) 0x20, (byte) 0x43, (byte) 0x61, (byte) 0x72, (byte) 0x64, (byte) 0x2e};

    /**
     * Installs this applet.
     *
     * @param bArray
     * the array containing installation parameters
     * @param bOffset
     * the starting offset in bArray
     * @param bLength
     * the length in bytes of the parameter data in bArray
     */
    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new DHApplet();
    }

    /**
     * Only this class's install method should create the applet object.
     */
    protected DHApplet() {
        register();

        // Creates an instance of the DH class and it's variables.
        dh = new DH();
    }

    /**
     * Processes an incoming APDU.
     *
     * @see APDU
     * @param apdu
     * the incoming APDU
     */
    public void process(APDU apdu) {
        //Insert your code here        
        if (selectingApplet()) {
            return;
        }

        byte[] apduBuffer = apdu.getBuffer();

        if (apduBuffer[ISO7816.OFFSET_CLA] == CLA) {
            switch (apduBuffer[ISO7816.OFFSET_INS]) {
                case INS_INIT:
                    if (apduBuffer[ISO7816.OFFSET_P1] == P1_INIT_WITH_PRIVKEY) {
                        dh.init(apduBuffer, ISO7816.OFFSET_CDATA);
                    } else {
                        dh.init();
                    }
                    return;

                case INS_GET:
                    if (apduBuffer[ISO7816.OFFSET_P1] == P1_Y) {
                        apdu.setOutgoing();
                        apdu.setOutgoingLength(DH.maxLength);
                        dh.getY(apduBuffer, (short) 0);
                        apdu.sendBytesLong(apduBuffer, (short) 0, DH.maxLength);
                    } else if (apduBuffer[ISO7816.OFFSET_P1] == P1_P) {
                        apdu.setOutgoing();
                        apdu.setOutgoingLength(DH.maxLength);
                        dh.getP(apduBuffer, (short) 0);
                        apdu.sendBytesLong(apduBuffer, (short) 0, DH.maxLength);
                    } else if (apduBuffer[ISO7816.OFFSET_P1] == P1_G) {
                        apdu.setOutgoing();
                        apdu.setOutgoingLength(DH.maxLength);
                        dh.getG(apduBuffer, (short) 0);
                        apdu.sendBytesLong(apduBuffer, (short) 0, DH.maxLength);
                    } else {
                        ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
                    }
                    return;

                case INS_SET:
                    if (apduBuffer[ISO7816.OFFSET_P1] == P1_Y) {
                        dh.setY(apduBuffer, ISO7816.OFFSET_CDATA, DH.maxLength, (short) 0);
                    } else if (apduBuffer[ISO7816.OFFSET_P1] == P1_P) {
                        dh.setP(apduBuffer, ISO7816.OFFSET_CDATA, DH.maxLength, (short) 0);
                    } else if (apduBuffer[ISO7816.OFFSET_P1] == P1_G) {
                        dh.setG(apduBuffer, ISO7816.OFFSET_CDATA, DH.maxLength, (short) 0);
                    } else {
                        ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
                    }
                    return;

                case INS_FINAL:
                    dh.doFinal(encKey);
                    return;

                case INS_TEST:
                    aesCipher.init(encKey, Cipher.MODE_ENCRYPT);
                    aesCipher.doFinal(reply, (short) 0, (short) reply.length, buffer, (short) 0);
                    apdu.setOutgoing();
                    apdu.setOutgoingLength((short) reply.length);
                    apdu.sendBytesLong(buffer, (short) 0, (short) reply.length);
                    return;

                default:
                    ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
            }
        } else {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }
    }
}
