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
package org.jivesoftware.smackx.omemo;

import org.jivesoftware.smack.Manager;
import org.jivesoftware.smack.SmackException;
import org.jivesoftware.smack.XMPPConnection;
import org.jivesoftware.smack.XMPPException;
import org.jivesoftware.smack.packet.Message;
import org.jivesoftware.smack.packet.Stanza;
import org.jivesoftware.smackx.disco.ServiceDiscoveryManager;
import org.jivesoftware.smackx.eme.element.ExplicitMessageEncryptionElement;
import org.jivesoftware.smackx.hints.element.StoreHint;
import org.jivesoftware.smackx.mam.MamManager;
import org.jivesoftware.smackx.muc.MultiUserChatManager;
import org.jivesoftware.smackx.muc.RoomInfo;
import org.jivesoftware.smackx.omemo.elements.OmemoElement;
import org.jivesoftware.smackx.omemo.elements.OmemoVAxolotlElement;
import org.jivesoftware.smackx.omemo.exceptions.CannotEstablishOmemoSessionException;
import org.jivesoftware.smackx.omemo.exceptions.CorruptedOmemoKeyException;
import org.jivesoftware.smackx.omemo.exceptions.CryptoFailedException;
import org.jivesoftware.smackx.omemo.exceptions.NoRawSessionException;
import org.jivesoftware.smackx.omemo.exceptions.UndecidedOmemoIdentityException;
import org.jivesoftware.smackx.omemo.internal.ClearTextMessage;
import org.jivesoftware.smackx.omemo.internal.OmemoDevice;
import org.jivesoftware.smackx.omemo.listener.OmemoMessageListener;
import org.jivesoftware.smackx.omemo.listener.OmemoMucMessageListener;
import org.jivesoftware.smackx.pubsub.PubSubException;
import org.jivesoftware.smackx.pubsub.packet.PubSub;
import org.jxmpp.jid.BareJid;
import org.jxmpp.jid.DomainBareJid;
import org.jxmpp.jid.EntityBareJid;
import org.jxmpp.jid.FullJid;

import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;
import java.util.WeakHashMap;
import java.util.logging.Level;
import java.util.logging.Logger;

import static org.jivesoftware.smackx.omemo.util.OmemoConstants.BODY_OMEMO_HINT;
import static org.jivesoftware.smackx.omemo.util.OmemoConstants.OMEMO;
import static org.jivesoftware.smackx.omemo.util.OmemoConstants.OMEMO_NAMESPACE_V_AXOLOTL;
import static org.jivesoftware.smackx.omemo.util.OmemoConstants.PEP_NODE_DEVICE_LIST_NOTIFY;

/**
 * Manager that allows sending messages encrypted with OMEMO.
 * This class also provides some methods useful for a client that implements OMEMO.
 *
 * @author Paul Schaub
 */
public final class OmemoManager extends Manager {
    private static final Logger LOGGER = Logger.getLogger(OmemoManager.class.getName());

    private static final WeakHashMap<XMPPConnection, OmemoManager> INSTANCES = new WeakHashMap<>();
    private OmemoService<?, ?, ?, ?, ?, ?, ?, ?, ?> service;

    /**
     * Mitigate vulnerability found in the OMEMO audit.
     * Activate when all clients support it. TODO: Remove this at a later point
     */
    public static boolean COMBINED_MESSAGE_KEY_AUTHTAG = true;

    /**
     * Ignore own other stale devices that we did not receive a message from for a period of time.
     * Ignoring means do not encrypt messages for them. This helps to mitigate stale devices that threaten
     * forward secrecy by never advancing ratchets.
     */
    private static boolean IGNORE_STALE_DEVICES = true;
    private static int IGNORE_STALE_DEVICE_AFTER_HOURS = 24 * 7;         //One week

    /**
     * Delete stale devices from the device list after a period of time.
     */
    private static boolean DELETE_STALE_DEVICES = true;
    private static int DELETE_STALE_DEVICE_AFTER_HOURS = 24 * 7 * 4;     //4 weeks

    /**
     * Upload a new signed prekey in intervals. This improves forward secrecy. Old keys are kept for some more time and
     * then deleted.
     */
    private static boolean RENEW_OLD_SIGNED_PREKEYS = false;
    private static int RENEW_OLD_SIGNED_PREKEYS_AFTER_HOURS = 24 * 7;    //One week
    private static int MAX_NUMBER_OF_STORED_SIGNED_PREKEYS = 4;

    /**
     * Add a plaintext body hint about omemo encryption to the message.
     */
    private static boolean ADD_OMEMO_HINT_BODY = true;

    /**
     * Add Explicit Message Encryption hint (XEP-0380) to the message.
     */
    private static boolean ADD_EME_ENCRYPTION_HINT = true;

    /**
     * Add MAM storage hint to allow the server to store messages that do not contain a body.
     */
    private static boolean ADD_MAM_STORAGE_HINT = true;

    /**
     * Private constructor to prevent multiple instances on a single connection (which probably would be bad!).
     *
     * @param connection connection
     */
    private OmemoManager(XMPPConnection connection) {
        super(connection);
    }

    /**
     * Get an instance of the OmemoManager for the given connection.
     *
     * @param connection Connection
     * @return an OmemoManager
     */
    public synchronized static OmemoManager getInstanceFor(XMPPConnection connection) {
        OmemoManager m = INSTANCES.get(connection);
        if (m == null) {
            m = new OmemoManager(connection);
            INSTANCES.put(connection, m);
        }
        return m;
    }

    /**
     * Set the OmemoService object containing a OmemoStore implementation.
     *
     * @param service OmemoService object
     */
    void setOmemoService(OmemoService<?, ?, ?, ?, ?, ?, ?, ?, ?> service) {
        if(this.service == null) {
            this.service = service;
        } else {
            LOGGER.log(Level.WARNING, "Setting the OmemoService multiple times is not allowed.");
        }
    }

    public void initialize() throws CorruptedOmemoKeyException, InterruptedException, SmackException.NoResponseException,
            SmackException.NotConnectedException, XMPPException.XMPPErrorException, SmackException.NotLoggedInException,
            PubSubException.NotALeafNodeException {
        throwIfNoServiceSet();
        getOmemoService().initialize();
    }

    /**
     * Get our connection.
     *
     * @return the connection of this manager
     */
    public XMPPConnection getConnection() {
        return connection();
    }

    /**
     * Return the OMEMO service object.
     *
     * @return omemoService
     */
    public OmemoService<?, ?, ?, ?, ?, ?, ?, ?, ?> getOmemoService() {
        return this.service;
    }

    /**
     * Clear all other devices except this one from our device list and republish the list.
     *
     * @throws SmackException if something goes wrong TODO: Is this still necessary?
     * @throws InterruptedException
     * @throws XMPPException.XMPPErrorException
     * @throws CorruptedOmemoKeyException
     */
    public void purgeDevices() throws SmackException, InterruptedException, XMPPException.XMPPErrorException, CorruptedOmemoKeyException {
        throwIfNoServiceSet();
        service.publishInformationIfNeeded(true);
    }

    /**
     * Generate fresh identity keys and bundle and publish it to the server.
     * @throws SmackException
     * @throws InterruptedException
     * @throws XMPPException.XMPPErrorException
     * @throws CorruptedOmemoKeyException
     */
    public void regenerate() throws SmackException, InterruptedException, XMPPException.XMPPErrorException, CorruptedOmemoKeyException {
        throwIfNoServiceSet();
        //create a new identity and publish new keys to the server
        getOmemoService().regenerate();
        getOmemoService().publishInformationIfNeeded(false);
    }

    /**
     * OMEMO encrypt a cleartext message for a single recipient.
     *
     * @param to      Recipients BareJid
     * @param message Message that will be encrypted. The body of the message will be encrypted.
     * @return new a new Message with the encrypted message in the 'encrypted' element and a hint for
     * OMEMO-uncapable clients in the body
     * @throws CryptoFailedException
     * @throws UndecidedOmemoIdentityException
     * @throws NoSuchAlgorithmException
     */
    public Message encrypt(BareJid to, Message message) throws CryptoFailedException, UndecidedOmemoIdentityException, NoSuchAlgorithmException {
        throwIfNoServiceSet();
        OmemoVAxolotlElement encrypted = service.processSendingMessage(to, message);
        return finishMessage(encrypted);
    }

    /**
     * OMEMO encrypt a cleartext message for multiple recipients.
     *
     * @param recipients Receipients BareJids
     * @param message    Message that will be encrypted. The body of the message will be encrypted.
     * @return new a new Message with the encrypted message in the 'encrypted' element and a hint for
     * OMEMO-incapable clients in the body
     * @throws CryptoFailedException            When something fails with the crypto
     * @throws UndecidedOmemoIdentityException  When the trust if the session with the recipient is not yet decided
     * @throws NoSuchAlgorithmException         When there is a missing algorithm
     */
    public Message encrypt(List<BareJid> recipients, Message message) throws CryptoFailedException, UndecidedOmemoIdentityException, NoSuchAlgorithmException {
        throwIfNoServiceSet();
        OmemoVAxolotlElement encrypted = getOmemoService().processSendingMessage(recipients, message);
        return finishMessage(encrypted);
    }

    /**
     * Send a ratchet update message. This can be used to advance the ratchet of a session in order to maintain forward
     * secrecy.
     *
     * @param recipient recipient
     * @throws UndecidedOmemoIdentityException      When the trust of session with the recipient is not decided yet
     * @throws CorruptedOmemoKeyException           When the used identityKeys are corrupted
     * @throws CryptoFailedException                When something fails with the crypto
     * @throws CannotEstablishOmemoSessionException When we can't establish a session with the recipient
     */
    public void sendRatchetUpdateMessage(OmemoDevice recipient)
            throws CorruptedOmemoKeyException, UndecidedOmemoIdentityException, CryptoFailedException,
            CannotEstablishOmemoSessionException {
        throwIfNoServiceSet();
        getOmemoService().sendOmemoRatchetUpdateMessage(recipient, false);
    }

    /**
     * Create a new KeyTransportElement. This message will contain the AES-Key and IV that can be used eg. for encrypted
     * Jingle file transfer.
     *
     * @param aesKey    AES key to transport
     * @param iv        Initialization vector
     * @param to        list of recipient devices
     * @return          KeyTransportMessage
     * @throws UndecidedOmemoIdentityException      When the trust of session with the recipient is not decided yet
     * @throws CorruptedOmemoKeyException           When the used identityKeys are corrupted
     * @throws CryptoFailedException                When something fails with the crypto
     * @throws CannotEstablishOmemoSessionException When we can't establish a session with the recipient
     */
    public OmemoVAxolotlElement createKeyTransportElement(byte[] aesKey, byte[] iv, OmemoDevice ... to)
            throws UndecidedOmemoIdentityException, CorruptedOmemoKeyException, CryptoFailedException,
            CannotEstablishOmemoSessionException {
        throwIfNoServiceSet();
        return getOmemoService().prepareOmemoKeyTransportElement(aesKey, iv, to);
    }

    /**
     * Decrypt an OMEMO message. This method comes handy when dealing with messages that were not automatically
     * decrypted by smack-omemo, eg. MAM query messages.
     * @param sender sender of the message
     * @param omemoMessage message
     * @return decrypted message
     * @throws InterruptedException                 Exception
     * @throws SmackException.NoResponseException   Exception
     * @throws SmackException.NotConnectedException Exception
     * @throws CryptoFailedException                When decryption fails
     * @throws XMPPException.XMPPErrorException     Exception
     * @throws CorruptedOmemoKeyException           When the used keys are invalid
     * @throws NoRawSessionException                When there is no double ratchet session found for this message
     */
    public ClearTextMessage decrypt(BareJid sender, Message omemoMessage) throws InterruptedException, SmackException.NoResponseException, SmackException.NotConnectedException, CryptoFailedException, XMPPException.XMPPErrorException, CorruptedOmemoKeyException, NoRawSessionException {
        throwIfNoServiceSet();
        return getOmemoService().processLocalMessage(sender, omemoMessage);
    }

    /**
     * Return a list of all OMEMO messages that were found in the MAM query result, that could be successfully decrypted.
     * Normal cleartext messages are also added to this list.
     *
     * @param mamQueryResult mamQueryResult
     * @return list of decrypted OmemoMessages
     * @throws InterruptedException                 Exception
     * @throws XMPPException.XMPPErrorException     Exception
     * @throws SmackException.NotConnectedException Exception
     * @throws SmackException.NoResponseException   Exception
     */
    public List<ClearTextMessage> decryptMamQueryResult(MamManager.MamQueryResult mamQueryResult) throws InterruptedException, XMPPException.XMPPErrorException, SmackException.NotConnectedException, SmackException.NoResponseException {
        throwIfNoServiceSet();
        List<ClearTextMessage> l = new ArrayList<>();
        l.addAll(getOmemoService().decryptMamQueryResult(mamQueryResult));
        return l;
    }

    /**
     * Create a new Message from a encrypted OmemoMessageElement.
     * Add ourselves as the sender and the encrypted element.
     * Also tell the server to store the message despite a possible missing body.
     * The body will be set to a hint message that we are using OMEMO.
     *
     * @param encrypted OmemoMessageElement
     * @return Message containing the OMEMO element and some additional information
     */
    Message finishMessage(OmemoVAxolotlElement encrypted) {
        if (encrypted == null) {
            return null;
        }

        Message chatMessage = new Message();
        chatMessage.setFrom(connection().getUser().asBareJid());
        chatMessage.addExtension(encrypted);

        if(getAddOmemoHintBody()) {
            chatMessage.setBody(BODY_OMEMO_HINT);
        }

        if(getAddMAMStorageProcessingHint()) {
            StoreHint.set(chatMessage);
        }

        if(getAddEmeEncryptionHint()) {
            chatMessage.addExtension(new ExplicitMessageEncryptionElement(OMEMO_NAMESPACE_V_AXOLOTL, OMEMO));
        }

        return chatMessage;
    }

    /**
     * Returns true, if the device resource has announced OMEMO support.
     * Throws an IllegalArgumentException if the provided FullJid does not have a resource part.
     *
     * @param fullJid jid of a resource
     * @return true if resource supports OMEMO
     * @throws XMPPException.XMPPErrorException     if
     * @throws SmackException.NotConnectedException something
     * @throws InterruptedException                 goes
     * @throws SmackException.NoResponseException   wrong
     */
    public boolean resourceSupportsOmemo(FullJid fullJid) throws XMPPException.XMPPErrorException, SmackException.NotConnectedException, InterruptedException, SmackException.NoResponseException {
        if(fullJid.hasNoResource()) {
            throw new IllegalArgumentException("Jid "+fullJid+" has no resource part.");
        }
        return ServiceDiscoveryManager.getInstanceFor(connection()).discoverInfo(fullJid).containsFeature(PEP_NODE_DEVICE_LIST_NOTIFY);
    }

    /**
     * Returns true, if the MUC with the EntityBareJid multiUserChat is non-anonymous and members only (prerequisite
     * for OMEMO encryption in MUC).
     *
     * @param multiUserChat EntityBareJid of the MUC
     * @return true if chat supports OMEMO
     * @throws XMPPException.XMPPErrorException     if
     * @throws SmackException.NotConnectedException something
     * @throws InterruptedException                 goes
     * @throws SmackException.NoResponseException   wrong
     */
    public boolean multiUserChatSupportsOmemo(EntityBareJid multiUserChat) throws XMPPException.XMPPErrorException, SmackException.NotConnectedException, InterruptedException, SmackException.NoResponseException {
        RoomInfo roomInfo = MultiUserChatManager.getInstanceFor(connection()).getRoomInfo(multiUserChat);
        return roomInfo.isNonanonymous() && roomInfo.isMembersOnly();
    }

    /**
     * Returns true, if the Server supports PEP.
     *
     * @param server domainBareJid of the server to test
     * @return true if server supports pep
     * @throws XMPPException.XMPPErrorException
     * @throws SmackException.NotConnectedException
     * @throws InterruptedException
     * @throws SmackException.NoResponseException
     */
    public boolean serverSupportsOmemo(DomainBareJid server) throws XMPPException.XMPPErrorException, SmackException.NotConnectedException, InterruptedException, SmackException.NoResponseException {
        return ServiceDiscoveryManager.getInstanceFor(connection()).discoverInfo(server).containsFeature(PubSub.NAMESPACE);
    }

    /**
     * Return the fingerprint of our identity key.
     *
     * @return fingerprint
     */
    public String getOurFingerprint() {
        throwIfNoServiceSet();
        return getOmemoService().getOmemoStore().getFingerprint();
    }

    public void addOmemoMessageListener(OmemoMessageListener listener) {
        getOmemoService().addOmemoMessageListener(listener);
    }

    public void removeOmemoMessageListener(OmemoMessageListener listener) {
        getOmemoService().removeOmemoMessageListener(listener);
    }

    public void addOmemoMucMessageListener(OmemoMucMessageListener listener) {
        getOmemoService().addOmemoMucMessageListener(listener);
    }

    public void removeOmemoMucMessageListener(OmemoMucMessageListener listener) {
        getOmemoService().removeOmemoMucMessageListener(listener);
    }

    public void buildSessionWith(OmemoDevice device) throws CannotEstablishOmemoSessionException, CorruptedOmemoKeyException {
        getOmemoService().buildSessionFromOmemoBundle(device);
    }

    public void requestDeviceListUpdateFor(BareJid contact) throws SmackException.NotConnectedException, InterruptedException, SmackException.NoResponseException {
        getOmemoService().refreshDeviceList(contact);
    }

    /**
     * Rotate the signedPreKey published in our OmemoBundle. This should be done every now and then (7-14 days).
     * The old signedPreKey should be kept for some more time (a month or so) to enable decryption of messages
     * that have been sent since the key was changed.
     *
     * @throws CorruptedOmemoKeyException When the IdentityKeyPair is damaged.
     * @throws InterruptedException XMPP error
     * @throws XMPPException.XMPPErrorException XMPP error
     * @throws SmackException.NotConnectedException XMPP error
     * @throws SmackException.NoResponseException XMPP error
     * @throws PubSubException.NotALeafNodeException if the bundle node on the server is a CollectionNode
     */
    public void rotateSignedPreKey() throws CorruptedOmemoKeyException, InterruptedException, XMPPException.XMPPErrorException, SmackException.NotConnectedException, SmackException.NoResponseException, PubSubException.NotALeafNodeException {
        throwIfNoServiceSet();
        //generate key
        getOmemoService().getOmemoStore().changeSignedPreKey();
        //publish
        getOmemoService().publishInformationIfNeeded(false);
    }

    /**
     * Return true, if the given Stanza contains an OMEMO element 'encrypted'.
     * @param stanza stanza
     * @return true if stanza has extension 'encrypted'
     */
    public static boolean stanzaContainsOmemoElement(Stanza stanza) {
        return stanza.hasExtension(OmemoElement.ENCRYPTED, OMEMO_NAMESPACE_V_AXOLOTL);
    }

    /**
     * Throw an IllegalStateException if no OmemoService is set.
     */
    private void throwIfNoServiceSet() {
        if(service == null) {
            throw new IllegalStateException("No OmemoService set in OmemoManager.");
        }
    }

    public static void setIgnoreStaleDevices(boolean ignore) {
        IGNORE_STALE_DEVICES = ignore;
    }

    public static boolean getIgnoreStaleDevices() {
        return IGNORE_STALE_DEVICES;
    }

    public static void setIgnoreStaleDevicesAfterHours(int hours) {
        IGNORE_STALE_DEVICE_AFTER_HOURS = hours;
    }

    public static int getIgnoreStaleDevicesAfterHours() {
        return IGNORE_STALE_DEVICE_AFTER_HOURS;
    }

    public static void setDeleteStaleDevices(boolean delete) {
        DELETE_STALE_DEVICES = delete;
    }

    public static boolean getDeleteStaleDevices() {
        return DELETE_STALE_DEVICES;
    }

    public static void setDeleteStaleDevicesAfterHours(int hours) {
        DELETE_STALE_DEVICE_AFTER_HOURS = hours;
    }

    public static int getDeleteStaleDevicesAfterHours() {
        return DELETE_STALE_DEVICE_AFTER_HOURS;
    }

    public static void setRenewOldSignedPreKeys(boolean renew) {
        RENEW_OLD_SIGNED_PREKEYS = renew;
    }

    public static boolean getRenewOldSignedPreKeys() {
        return RENEW_OLD_SIGNED_PREKEYS;
    }

    public static void setRenewOldSignedPreKeysAfterHours(int hours) {
        RENEW_OLD_SIGNED_PREKEYS_AFTER_HOURS = hours;
    }

    public static int getRenewOldSignedPreKeysAfterHours() {
        return RENEW_OLD_SIGNED_PREKEYS_AFTER_HOURS;
    }

    public static void setMaxNumberOfStoredSignedPreKeys(int number) {
        MAX_NUMBER_OF_STORED_SIGNED_PREKEYS = number;
    }

    public static int getMaxNumberOfStoredSignedPreKeys() {
        return MAX_NUMBER_OF_STORED_SIGNED_PREKEYS;
    }

    public static void setAddOmemoHintBody(boolean addHint) {
        ADD_OMEMO_HINT_BODY = addHint;
    }

    public static boolean getAddOmemoHintBody() {
        return ADD_OMEMO_HINT_BODY;
    }

    public static void setAddEmeEncryptionHint(boolean addHint) {
        ADD_EME_ENCRYPTION_HINT = addHint;
    }

    public static boolean getAddEmeEncryptionHint() {
        return ADD_EME_ENCRYPTION_HINT;
    }

    public static void setAddMAMStorageProcessingHint(boolean addStorageHint) {
        ADD_MAM_STORAGE_HINT = addStorageHint;
    }

    public static boolean getAddMAMStorageProcessingHint() {
        return ADD_MAM_STORAGE_HINT;
    }

    public static void setHardenMessageEncryption(boolean harden) {
        COMBINED_MESSAGE_KEY_AUTHTAG = harden;
    }
}
