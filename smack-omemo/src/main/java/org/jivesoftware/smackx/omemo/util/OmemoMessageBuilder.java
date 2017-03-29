/**
 *
 * Copyright the original author or authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.jivesoftware.smackx.omemo.util;

import org.jivesoftware.smack.util.StringUtils;
import org.jivesoftware.smackx.omemo.internal.OmemoSession;
import org.jivesoftware.smackx.omemo.OmemoStore;
import org.jivesoftware.smackx.omemo.elements.OmemoMessageElement;
import org.jivesoftware.smackx.omemo.exceptions.CannotEstablishOmemoSessionException;
import org.jivesoftware.smackx.omemo.exceptions.CryptoFailedException;
import org.jivesoftware.smackx.omemo.exceptions.CorruptedOmemoKeyException;
import org.jivesoftware.smackx.omemo.exceptions.UndecidedOmemoIdentityException;
import org.jivesoftware.smackx.omemo.internal.CiphertextTuple;
import org.jivesoftware.smackx.omemo.internal.OmemoDevice;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.util.ArrayList;

import static org.jivesoftware.smackx.omemo.util.OmemoConstants.Crypto.KEYTYPE;
import static org.jivesoftware.smackx.omemo.util.OmemoConstants.Crypto.CIPHERMODE;
import static org.jivesoftware.smackx.omemo.util.OmemoConstants.Crypto.PROVIDER;

/**
 * Class used to build OMEMO messages.
 *
 * @param <T_IdKeyPair> IdentityKeyPair class
 * @param <T_IdKey>     IdentityKey class
 * @param <T_PreKey>    PreKey class
 * @param <T_SigPreKey> SignedPreKey class
 * @param <T_Sess>      Session class
 * @param <T_Addr>      Address class
 * @param <T_ECPub>     Elliptic Curve PublicKey class
 * @param <T_Bundle>    Bundle class
 * @param <T_Ciph>      Cipher class
 * @author Paul Schaub
 */
public class OmemoMessageBuilder<T_IdKeyPair, T_IdKey, T_PreKey, T_SigPreKey, T_Sess, T_Addr, T_ECPub, T_Bundle, T_Ciph> {
    private final OmemoStore<T_IdKeyPair, T_IdKey, T_PreKey, T_SigPreKey, T_Sess, T_Addr, T_ECPub, T_Bundle, T_Ciph> omemoStore;

    private byte[] messageKey = generateKey();
    private final byte[] initializationVector = generateIv();

    private byte[] ciphertextMessage;
    private final ArrayList<OmemoMessageElement.OmemoHeader.Key> keys = new ArrayList<>();

    public OmemoMessageBuilder(OmemoStore<T_IdKeyPair, T_IdKey, T_PreKey, T_SigPreKey, T_Sess, T_Addr, T_ECPub, T_Bundle, T_Ciph> omemoStore, String message)
            throws NoSuchPaddingException, BadPaddingException, InvalidKeyException, NoSuchAlgorithmException, IllegalBlockSizeException,
            UnsupportedEncodingException, NoSuchProviderException, InvalidAlgorithmParameterException {
        this.omemoStore = omemoStore;
        this.setMessage(message);
    }

    /**
     * Create an AES messageKey and use it to encrypt the message.
     * Optionally append the Auth Tag of the encrypted message to the messageKey afterwards.
     *
     * @param message content of the message
     * @throws NoSuchPaddingException               When no Cipher could be instantiated.
     * @throws NoSuchAlgorithmException             when no Cipher could be instantiated.
     * @throws NoSuchProviderException              when BouncyCastle could not be found.
     * @throws InvalidAlgorithmParameterException   when the Cipher could not be initialized
     * @throws InvalidKeyException                  when the generated key is invalid
     * @throws UnsupportedEncodingException         when UTF8 is unavailable
     * @throws BadPaddingException                  when cipher.doFinal gets wrong padding
     * @throws IllegalBlockSizeException            when cipher.doFinal gets wrong Block size.
     */
    private void setMessage(String message) throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException, InvalidKeyException, UnsupportedEncodingException, BadPaddingException, IllegalBlockSizeException {
        //Encrypt message body
        SecretKey secretKey = new SecretKeySpec(messageKey, KEYTYPE);
        IvParameterSpec ivSpec = new IvParameterSpec(initializationVector);
        Cipher cipher = Cipher.getInstance(CIPHERMODE, PROVIDER);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);

        byte[] body = (message.getBytes(StringUtils.UTF8));
        byte[] ciphertext = cipher.doFinal(body);

        if (OmemoConstants.APPEND_AUTH_TAG_TO_MESSAGE_KEY) {
            byte[] clearKeyWithAuthTag = new byte[messageKey.length + 16];
            byte[] cipherTextWithoutAuthTag = new byte[ciphertext.length - 16];

            System.arraycopy(messageKey, 0, clearKeyWithAuthTag, 0, 16);
            System.arraycopy(ciphertext, 0, cipherTextWithoutAuthTag, 0, cipherTextWithoutAuthTag.length);
            System.arraycopy(ciphertext, ciphertext.length - 16, clearKeyWithAuthTag, 16, 16);

            ciphertextMessage = cipherTextWithoutAuthTag;
            messageKey = clearKeyWithAuthTag;
        } else {
            ciphertextMessage = ciphertext;
        }
    }

    /**
     * Add a new recipient device to the message.
     *
     * @param device recipient device
     * @throws CannotEstablishOmemoSessionException when no session can be established
     * @throws CryptoFailedException                when encrypting the messageKey fails
     */
    public void addRecipient(OmemoDevice device) throws CannotEstablishOmemoSessionException,
            CryptoFailedException, UndecidedOmemoIdentityException, CorruptedOmemoKeyException {
        //For each recipient device: Encrypt message key with session key
        if (!omemoStore.containsRawSession(device)) {
            omemoStore.getOmemoService().buildSessionFromOmemoBundle(device);
        }

        OmemoSession<T_IdKeyPair, T_IdKey, T_PreKey, T_SigPreKey, T_Sess, T_Addr, T_ECPub, T_Bundle, T_Ciph> session =
                omemoStore.getOmemoSessionOf(device);

        if (session != null) {
            if (!omemoStore.isDecidedOmemoIdentity(device, session.getIdentityKey())) {
                //Warn user of undecided device
                throw new UndecidedOmemoIdentityException(device);
            }

            if (omemoStore.isTrustedOmemoIdentity(device, session.getIdentityKey())) {
                //Encrypt key and save to header
                CiphertextTuple encryptedKey = session.encryptMessageKey(messageKey);
                keys.add(new OmemoMessageElement.OmemoHeader.Key(encryptedKey.getCiphertext(), device.getDeviceId(), encryptedKey.isPreKeyMessage()));
            }
        } else {
            throw new CannotEstablishOmemoSessionException("Can't find or establish session with " + device);
        }
    }

    /**
     * Assemble an OmemoMessageElement from the current state of the builder.
     *
     * @return OmemoMessageElement
     */
    public OmemoMessageElement finish() {
        OmemoMessageElement.OmemoHeader header = new OmemoMessageElement.OmemoHeader(
                omemoStore.loadOmemoDeviceId(),
                keys,
                initializationVector
        );
        return new OmemoMessageElement(header, ciphertextMessage);
    }

    /**
     * Generate a new AES key used to encrypt the message.
     *
     * @return new AES key
     */
    private static byte[] generateKey() throws NoSuchAlgorithmException {
        KeyGenerator generator = KeyGenerator.getInstance(KEYTYPE);
        generator.init(128);
        return generator.generateKey().getEncoded();
    }

    /**
     * Generate a 16 byte initialization vector for AES encryption.
     *
     * @return iv
     */
    private static byte[] generateIv() {
        SecureRandom random = new SecureRandom();
        byte[] iv = new byte[16];
        random.nextBytes(iv);
        return iv;
    }
}
