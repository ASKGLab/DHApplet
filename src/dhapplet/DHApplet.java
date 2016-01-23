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
    public final static byte BLANK = (byte) 0x00;

    //Variables
    public DH dh;
    private AESKey encKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES_TRANSIENT_RESET, KeyBuilder.LENGTH_AES_128, false);

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

        byte[] buffer = apdu.getBuffer();

        if (buffer[ISO7816.OFFSET_CLA] == CLA) {
            switch (buffer[ISO7816.OFFSET_INS]) {
                case INS_INIT:
                    dh.init();
                    return;

                case INS_GET:
                    if (buffer[ISO7816.OFFSET_P1] == P1_Y) {
                        
                    } else if (buffer[ISO7816.OFFSET_P1] == P1_P) {

                    } else if (buffer[ISO7816.OFFSET_P1] == P1_G) {

                    } else {
                        ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
                    }
                    return;

                case INS_SET:
                    if (buffer[ISO7816.OFFSET_P1] == P1_Y) {

                    } else if (buffer[ISO7816.OFFSET_P1] == P1_P) {

                    } else if (buffer[ISO7816.OFFSET_P1] == P1_G) {

                    } else {
                        ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
                    }
                    return;
                    
                case INS_FINAL:
                    dh.doFinal(encKey);
                    return;

                case INS_TEST:
                    return;
                    
                default:
                    ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
            }
        } else {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }
    }
}
