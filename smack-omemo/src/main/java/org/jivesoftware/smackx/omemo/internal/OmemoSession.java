/**
 *
 * Copyright 2017 Paul Schaub
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
package org.jivesoftware.smackx.omemo.internal;

import org.jivesoftware.smack.packet.Message;
import org.jivesoftware.smack.util.StringUtils;
import org.jivesoftware.smackx.omemo.OmemoStoreConnector;
import org.jivesoftware.smackx.omemo.elements.OmemoElement;
import org.jivesoftware.smackx.omemo.exceptions.CryptoFailedException;
import org.jivesoftware.smackx.omemo.exceptions.NoRawSessionException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.logging.Level;
import java.util.logging.Logger;

import static org.jivesoftware.smackx.omemo.util.OmemoConstants.Crypto.CIPHERMODE;
import static org.jivesoftware.smackx.omemo.util.OmemoConstants.Crypto.KEYTYPE;
import static org.jivesoftware.smackx.omemo.util.OmemoConstants.Crypto.PROVIDER;

/**
 * This class represents a OMEMO session between us and another device.
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
public abstract class OmemoSession<T_IdKeyPair, T_IdKey, T_PreKey, T_SigPreKey, T_Sess, T_Addr, T_ECPub, T_Bundle, T_Ciph> {
    private static final Logger LOGGER = Logger.getLogger(OmemoSession.class.getName());

    protected final T_Ciph cipher;
    protected final OmemoStoreConnector<T_IdKeyPair, T_IdKey, T_PreKey, T_SigPreKey, T_Sess, T_Addr, T_ECPub, T_Bundle, T_Ciph> omemoStoreConnector;
    protected final OmemoDevice remoteDevice;
    protected T_IdKey identityKey;
    protected int preKeyId = -1;

    /**
     * Constructor used when we establish the session.
     *
     * @param omemoStoreConnector   OmemoStoreConnector where we want to store the session and get key information from
     * @param remoteDevice the OmemoDevice we want to establish the session with
     * @param identityKey  identityKey of the recipient
     */
    public OmemoSession(OmemoStoreConnector<T_IdKeyPair, T_IdKey, T_PreKey, T_SigPreKey, T_Sess, T_Addr, T_ECPub, T_Bundle, T_Ciph> omemoStoreConnector,
                        OmemoDevice remoteDevice, T_IdKey identityKey) {
        this(omemoStoreConnector, remoteDevice);
        this.identityKey = identityKey;
    }

    /**
     * Another constructor used when they establish the session with us.
     *
     * @param omemoStoreConnector   OmemoStore we want to store the session and their key in
     * @param remoteDevice identityKey of the partner
     */
    public OmemoSession(OmemoStoreConnector<T_IdKeyPair, T_IdKey, T_PreKey, T_SigPreKey, T_Sess, T_Addr, T_ECPub, T_Bundle, T_Ciph> omemoStoreConnector,
                        OmemoDevice remoteDevice) {
        this.omemoStoreConnector = omemoStoreConnector;
        this.remoteDevice = remoteDevice;
        this.cipher = createCipher(remoteDevice);
    }

    /**
     * Try to decrypt the transported message key using the double ratchet session.
     * @param element omemoElement
     * @param keyId our keyId
     * @return tuple of cipher generated from the unpacked message key and the authtag
     * @throws CryptoFailedException if decryption using the double ratchet fails
     * @throws NoRawSessionException if we have no session, but the element was NOT a PreKeyMessage
     */
    public CipherAndAuthTag decryptTransportedKey(OmemoElement element, int keyId) throws CryptoFailedException,
            NoRawSessionException {
        byte[] unpackedKey = null;
        //Find key with our id
        for (OmemoElement.OmemoHeader.Key k : element.getHeader().getKeys()) {
            if (k.getId() == keyId) {
                try {
                    unpackedKey = decryptMessageKey(k.getData());
                    break;
                } catch (CryptoFailedException e) {
                    LOGGER.log(Level.SEVERE, "decryptMessageElement failed: " + e.getMessage());
                    //TODO: Wise to ignore the exception?
                    //The issue is, there might be multiple keys with our id, but we can only decrypt one.
                    //So we can't throw the exception, when decrypting the first duplicate which is not for us.
                    //Just print the exception for now.
                }
            }
        }

        if (unpackedKey == null) {
            throw new CryptoFailedException("Transported key could not be decrypted, since the message key could not be unpacked.");
        }

        byte[] messageKey = new byte[16];
        byte[] authTag = new byte[16];
        if (unpackedKey.length == 32) {
            //copy key part into messageKey
            System.arraycopy(unpackedKey, 0, messageKey, 0, 16);
            //copy tag part into authTag
            System.arraycopy(unpackedKey, 16, authTag, 0,16);
        } else {
            throw new CryptoFailedException("MessageKey has wrong length: "+unpackedKey.length+". Probably legacy auth tag format.");
        }

        // Create and initialize cipher from transported key
        Cipher transportedCipher;
        try {
            transportedCipher = Cipher.getInstance(CIPHERMODE, PROVIDER);
            SecretKeySpec keySpec = new SecretKeySpec(messageKey, KEYTYPE);
            IvParameterSpec ivSpec = new IvParameterSpec(element.getHeader().getIv());
            transportedCipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
        } catch (NoSuchAlgorithmException | java.security.InvalidKeyException |
                InvalidAlgorithmParameterException |
                NoSuchPaddingException | NoSuchProviderException e) {
            throw new CryptoFailedException(e);
        }

        return new CipherAndAuthTag(transportedCipher, authTag);
    }

    public Message decryptMessageElement(OmemoElement element, CipherAndAuthTag cipherAndAuthTag) throws CryptoFailedException {
        if(!element.isMessageElement()) {
            throw new IllegalArgumentException("decryptMessageElement cannot decrypt OmemoElement which is no MessageElement!");
        }

        byte[] encryptedBody = new byte[element.getPayload().length + 16];
        byte[] payload = element.getPayload();
        System.arraycopy(payload, 0, encryptedBody, 0, payload.length);
        System.arraycopy(cipherAndAuthTag.getAuthTag(), 0, encryptedBody, payload.length, 16);

        try {
            String plaintext = new String(cipherAndAuthTag.getCipher().doFinal(encryptedBody), StringUtils.UTF8);
            Message decrypted = new Message();
            decrypted.setBody(plaintext);
            return decrypted;

        } catch (UnsupportedEncodingException | IllegalBlockSizeException | BadPaddingException e) {
            throw new CryptoFailedException("decryptMessageElement could not decipher message body: "+e.getMessage());
        }
    }

    /**
     * Try to decrypt the message.
     * First decrypt the message key using our session with the sender.
     * Second use the decrypted key to decrypt the message.
     * The decrypted content of the 'encrypted'-element becomes the body of the clear text message.
     *
     * @param element OmemoElement
     * @param keyId   the key we want to decrypt (usually our own device id)
     * @return message as plaintext
     * @throws CryptoFailedException
     * @throws NoRawSessionException
     */
    // TODO find solution for what we actually want to decrypt (String, Message, List<ExtensionElements>...)
    public Message decryptMessageElement(OmemoElement element, int keyId) throws CryptoFailedException, NoRawSessionException {
        if(!element.isMessageElement()) {
            throw new IllegalArgumentException("OmemoElement is not a messageElement!");
        }

        CipherAndAuthTag cipherAndAuthTag = decryptTransportedKey(element, keyId);
        return decryptMessageElement(element, cipherAndAuthTag);
    }

    /**
     * Create a new SessionCipher used to encrypt/decrypt keys. The cipher typically implements the ratchet and KDF-chains.
     *
     * @param contact    OmemoDevice
     * @return SessionCipher
     */
    public abstract T_Ciph createCipher(OmemoDevice contact);

    /**
     * Get the id of the preKey used to establish the session.
     *
     * @return id
     */
    public int getPreKeyId() {
        return this.preKeyId;
    }

    /**
     * Encrypt a message key for the recipient. This key can be deciphered by the recipient with its corresponding
     * session cipher. The key is then used to decipher the message.
     *
     * @param messageKey serialized key to encrypt
     * @return A CiphertextTuple containing the ciphertext and the messageType
     * @throws CryptoFailedException
     */
    public abstract CiphertextTuple encryptMessageKey(byte[] messageKey) throws CryptoFailedException;

    /**
     * Decrypt a messageKey using our sessionCipher. We can use that key to decipher the actual message.
     * Same as encryptMessageKey, just the other way round.
     *
     * @param encryptedKey encrypted key
     * @return serialized decrypted key or null
     * @throws CryptoFailedException when decryption fails.
     * @throws NoRawSessionException when no session was found in the double ratchet library
     */
    public abstract byte[] decryptMessageKey(byte[] encryptedKey) throws CryptoFailedException, NoRawSessionException;

    /**
     * Return the identityKey of the session.
     *
     * @return identityKey
     */
    public T_IdKey getIdentityKey() {
        return identityKey;
    }

    /**
     * Set the identityKey of the remote device.
     * @param identityKey identityKey
     */
    public void setIdentityKey(T_IdKey identityKey) {
        this.identityKey = identityKey;
    }

    /**
     * Return the fingerprint of the contacts identityKey.
     *
     * @return fingerprint or null
     */
    public String getFingerprint() {
        return (this.identityKey != null ? omemoStoreConnector.keyUtil().getFingerprint(this.identityKey) : null);
    }
}
