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

import org.jivesoftware.smack.AbstractXMPPConnection;
import org.jivesoftware.smack.ConnectionListener;
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
import org.jivesoftware.smackx.muc.MultiUserChat;
import org.jivesoftware.smackx.muc.MultiUserChatManager;
import org.jivesoftware.smackx.muc.RoomInfo;
import org.jivesoftware.smackx.omemo.elements.OmemoElement;
import org.jivesoftware.smackx.omemo.elements.OmemoVAxolotlElement;
import org.jivesoftware.smackx.omemo.exceptions.CannotEstablishOmemoSessionException;
import org.jivesoftware.smackx.omemo.exceptions.CorruptedOmemoKeyException;
import org.jivesoftware.smackx.omemo.exceptions.CryptoFailedException;
import org.jivesoftware.smackx.omemo.exceptions.NoRawSessionException;
import org.jivesoftware.smackx.omemo.exceptions.UndecidedOmemoIdentityException;
import org.jivesoftware.smackx.omemo.internal.CachedDeviceList;
import org.jivesoftware.smackx.omemo.internal.CipherAndAuthTag;
import org.jivesoftware.smackx.omemo.internal.ClearTextMessage;
import org.jivesoftware.smackx.omemo.internal.OmemoDevice;
import org.jivesoftware.smackx.omemo.internal.OmemoMessageInformation;
import org.jivesoftware.smackx.omemo.listener.OmemoMessageListener;
import org.jivesoftware.smackx.omemo.listener.OmemoMucMessageListener;
import org.jivesoftware.smackx.pubsub.PubSubException;
import org.jivesoftware.smackx.pubsub.packet.PubSub;
import org.jxmpp.jid.BareJid;
import org.jxmpp.jid.DomainBareJid;
import org.jxmpp.jid.EntityBareJid;
import org.jxmpp.jid.FullJid;
import org.jxmpp.jid.impl.JidCreate;
import org.jxmpp.stringprep.XmppStringprepException;

import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Random;
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

    private static final WeakHashMap<XMPPConnection, WeakHashMap<Integer,OmemoManager>> INSTANCES = new WeakHashMap<>();
    private final OmemoService<?, ?, ?, ?, ?, ?, ?, ?, ?> service;

    private final HashSet<OmemoMessageListener> omemoMessageListeners = new HashSet<>();
    private final HashSet<OmemoMucMessageListener> omemoMucMessageListeners = new HashSet<>();

    private int deviceId;

    /**
     * Private constructor to prevent multiple instances on a single connection (which probably would be bad!).
     *
     * @param connection connection
     */
    private OmemoManager(XMPPConnection connection, int deviceId) {
        super(connection);
        setConnectionListener();
        this.deviceId = deviceId;
        service = OmemoService.getInstance();
    }

    /**
     * Get an instance of the OmemoManager for the given connection.
     *
     * @param connection Connection
     * @param deviceId deviceId of the Manager. If the deviceId is null, a random id will be generated.
     * @return an OmemoManager
     */
    public synchronized static OmemoManager getInstanceFor(XMPPConnection connection, Integer deviceId) {
        WeakHashMap<Integer,OmemoManager> managersOfConnection = INSTANCES.get(connection);
        if(managersOfConnection == null) {
            managersOfConnection = new WeakHashMap<>();
            INSTANCES.put(connection, managersOfConnection);
        }

        Integer id = deviceId;

        if(id == null || id < 1) {
            id = randomDeviceId();
        }

        OmemoManager manager = managersOfConnection.get(id);
        if (manager == null) {
            manager = new OmemoManager(connection, id);
            managersOfConnection.put(id, manager);
        }
        return manager;
    }

    public synchronized static OmemoManager getInstanceFor(XMPPConnection connection) {
        BareJid user;
        if(connection.getUser() != null) {
            user = connection.getUser().asBareJid();
        } else {
            //This might be dangerous
            try {
                user = JidCreate.bareFrom(((AbstractXMPPConnection) connection).getConfiguration().getUsername());
            } catch (XmppStringprepException e) {
                throw new AssertionError("Username is not a valid Jid. " +
                        "Use OmemoManager.gerInstanceFor(Connection, deviceId) instead.");
            }
        }

        int defaulDeviceId = OmemoService.getInstance().getOmemoStoreBackend().getDefaultDeviceId(user);
        if (defaulDeviceId < 1) {
            defaulDeviceId = randomDeviceId();
            OmemoService.getInstance().getOmemoStoreBackend().setDefaultDeviceId(user, defaulDeviceId);
        }

        return getInstanceFor(connection, defaulDeviceId);
    }

    public synchronized static List<OmemoManager> getExistingManagersFor(XMPPConnection connection, List<Integer> deviceIds) {
        WeakHashMap<Integer, OmemoManager> managersOfConnection = INSTANCES.get(connection);
        ArrayList<OmemoManager> managers = new ArrayList<>();

        if(managersOfConnection == null) {
            return managers;
        }

        for(int deviceId : deviceIds) {
            OmemoManager m = managersOfConnection.get(deviceId);
            if(m != null) {
                managers.add(m);
            }
        }

        return managers;
    }

    public void initialize() throws CorruptedOmemoKeyException, InterruptedException, SmackException.NoResponseException,
            SmackException.NotConnectedException, XMPPException.XMPPErrorException, SmackException.NotLoggedInException,
            PubSubException.NotALeafNodeException {
        getOmemoService().initialize(this);
    }

    /**
     * Get our connection.
     *
     * @return the connection of this manager
     */
    XMPPConnection getConnection() {
        return connection();
    }

    /**
     * Return the OMEMO service object.
     *
     * @return omemoService
     */
    public OmemoService<?,?,?,?,?,?,?,?,?> getOmemoService() {
        throwIfNoServiceSet();
        return service;
    }

    /**
     * Clear all other devices except this one from our device list and republish the list.
     *
     * @throws InterruptedException
     * @throws XMPPException.XMPPErrorException
     * @throws CorruptedOmemoKeyException
     */
    public void purgeDevices() throws SmackException, InterruptedException, XMPPException.XMPPErrorException, CorruptedOmemoKeyException {
        getOmemoService().publishDeviceIdIfNeeded(this,true);
        getOmemoService().publishBundle(this);
    }

    /**
     * Generate fresh identity keys and bundle and publish it to the server.
     * @throws SmackException
     * @throws InterruptedException
     * @throws XMPPException.XMPPErrorException
     * @throws CorruptedOmemoKeyException
     */
    public void regenerate() throws SmackException, InterruptedException, XMPPException.XMPPErrorException, CorruptedOmemoKeyException {
        //create a new identity and publish new keys to the server
        getOmemoService().regenerate(this, null);
        getOmemoService().publishDeviceIdIfNeeded(this,false);
        getOmemoService().publishBundle(this);
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
        OmemoVAxolotlElement encrypted = getOmemoService().processSendingMessage(this, to, message);
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
        OmemoVAxolotlElement encrypted = getOmemoService().processSendingMessage(this, recipients, message);
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
        getOmemoService().sendOmemoRatchetUpdateMessage(this, recipient, false);
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
        return getOmemoService().prepareOmemoKeyTransportElement(this, aesKey, iv, to);
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
        return getOmemoService().processLocalMessage(this, sender, omemoMessage);
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
        List<ClearTextMessage> l = new ArrayList<>();
        l.addAll(getOmemoService().decryptMamQueryResult(this, mamQueryResult));
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

        if(OmemoConfiguration.getInstance().getAddOmemoHintBody()) {
            chatMessage.setBody(BODY_OMEMO_HINT);
        }

        if(OmemoConfiguration.getInstance().getAddMAMStorageProcessingHint()) {
            StoreHint.set(chatMessage);
        }

        if(OmemoConfiguration.getInstance().getAddEmeEncryptionHint()) {
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
        return getOmemoService().getOmemoStoreBackend().getFingerprint(this);
    }

    public String getFingerprint(OmemoDevice device) throws CannotEstablishOmemoSessionException {
        if(device.equals(new OmemoDevice(getOwnJid(), getDeviceId()))) {
            return getOurFingerprint();
        }

        return getOmemoService().getOmemoStoreBackend().getFingerprint(this, device);
    }

    public HashMap<Integer, String> getActiveFingerprints(BareJid contact) {
        HashMap<Integer, String> fingerprints = new HashMap<>();
        CachedDeviceList deviceList = getOmemoService().getOmemoStoreBackend().loadCachedDeviceList(this, contact);
        for(int id : deviceList.getActiveDevices()) {
            try {
                fingerprints.put(id, getFingerprint(new OmemoDevice(contact, id)));
            } catch (CannotEstablishOmemoSessionException e) {
                LOGGER.log(Level.WARNING, "Could not build session with device "+id+" of user "+contact+": "+e.getMessage());
            }
        }
        return fingerprints;
    }

    public void addOmemoMessageListener(OmemoMessageListener listener) {
        omemoMessageListeners.add(listener);
    }

    public void removeOmemoMessageListener(OmemoMessageListener listener) {
        omemoMessageListeners.remove(listener);
    }

    public void addOmemoMucMessageListener(OmemoMucMessageListener listener) {
        omemoMucMessageListeners.add(listener);
    }

    public void removeOmemoMucMessageListener(OmemoMucMessageListener listener) {
        omemoMucMessageListeners.remove(listener);
    }

    public void buildSessionWith(OmemoDevice device) throws CannotEstablishOmemoSessionException, CorruptedOmemoKeyException {
        getOmemoService().buildSessionFromOmemoBundle(this, device);
    }

    public void requestDeviceListUpdateFor(BareJid contact) throws SmackException.NotConnectedException, InterruptedException, SmackException.NoResponseException {
        getOmemoService().refreshDeviceList(this, contact);
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
        //generate key
        getOmemoService().getOmemoStoreBackend().changeSignedPreKey(this);
        //publish
        getOmemoService().publishDeviceIdIfNeeded(this, false);
        getOmemoService().publishBundle(this);
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

    private void setConnectionListener() {
        connection().addConnectionListener(new ConnectionListener() {
            @Override
            public void connected(XMPPConnection connection) {
                LOGGER.log(Level.INFO, "connected");
            }

            @Override
            public void authenticated(XMPPConnection connection, boolean resumed) {
                LOGGER.log(Level.INFO, "authenticated: "+resumed);
                if(resumed) {
                    return;
                }
                try {
                    getOmemoService().initialize(OmemoManager.this);
                } catch (InterruptedException | CorruptedOmemoKeyException | PubSubException.NotALeafNodeException | SmackException.NotLoggedInException | SmackException.NoResponseException | SmackException.NotConnectedException | XMPPException.XMPPErrorException e) {
                    LOGGER.log(Level.SEVERE, "connectionListener.authenticated() failed to initialize OmemoManager: "+e.getMessage());
                }
            }

            @Override
            public void connectionClosed() {

            }

            @Override
            public void connectionClosedOnError(Exception e) {
                connectionClosed();
            }

            @Override
            public void reconnectionSuccessful() {

            }

            @Override
            public void reconnectingIn(int seconds) {

            }

            @Override
            public void reconnectionFailed(Exception e) {

            }
        });
    }

    public static int randomDeviceId() {
        int i = new Random().nextInt(Integer.MAX_VALUE);

        if(i == 0) {
            return randomDeviceId();
        }

        return Math.abs(i);
    }

    BareJid getOwnJid() {
        return connection().getUser().asBareJid();
    }

    public int getDeviceId() {
        return deviceId;
    }

    public OmemoDevice getOwnDevice() {
        return new OmemoDevice(getOwnJid(), getDeviceId());
    }

    void setDeviceId(int nDeviceId) {
        INSTANCES.get(connection()).remove(getDeviceId());
        INSTANCES.get(connection()).put(nDeviceId, this);
        this.deviceId = nDeviceId;
    }

    /**
     * Notify all registered OmemoMessageListeners about a received OmemoMessage.
     *
     * @param decryptedBody      decrypted Body element of the message
     * @param encryptedMessage   unmodified message as it was received
     * @param wrappingMessage    message that wrapped the incoming message
     * @param messageInformation information about the messages encryption (used identityKey, carbon...)
     */
    void notifyOmemoMessageReceived(String decryptedBody, Message encryptedMessage, Message wrappingMessage, OmemoMessageInformation messageInformation) {
        for (OmemoMessageListener l : omemoMessageListeners) {
            l.onOmemoMessageReceived(decryptedBody, encryptedMessage, wrappingMessage, messageInformation);
        }
    }

    void notifyOmemoKeyTransportMessageReceived(CipherAndAuthTag cipherAndAuthTag, Message transportingMessage,
                                                Message wrappingMessage, OmemoMessageInformation information) {
        for (OmemoMessageListener l : omemoMessageListeners) {
            l.onOmemoKeyTransportReceived(cipherAndAuthTag, transportingMessage, wrappingMessage, information);
        }
    }

    /**
     * Notify all registered OmemoMucMessageListeners of an incoming OmemoMessageElement in a MUC.
     *
     * @param muc              MultiUserChat the message was received in
     * @param from             BareJid of the user that sent the message
     * @param decryptedBody    decrypted body
     * @param message          original message with encrypted content
     * @param wrappingMessage  wrapping message (in case of carbon copy)
     * @param omemoInformation information about the encryption of the message
     */
    void notifyOmemoMucMessageReceived(MultiUserChat muc, BareJid from, String decryptedBody, Message message,
                                               Message wrappingMessage, OmemoMessageInformation omemoInformation) {
        for (OmemoMucMessageListener l : omemoMucMessageListeners) {
            l.onOmemoMucMessageReceived(muc, from, decryptedBody, message,
                    wrappingMessage, omemoInformation);
        }
    }

    void notifyOmemoMucKeyTransportMessageReceived(MultiUserChat muc, BareJid from, CipherAndAuthTag cipherAndAuthTag,
                                                   Message transportingMessage, Message wrappingMessage,
                                                   OmemoMessageInformation messageInformation) {
        for(OmemoMucMessageListener l : omemoMucMessageListeners) {
            l.onOmemoKeyTransportReceived(muc, from, cipherAndAuthTag,
                    transportingMessage, wrappingMessage, messageInformation);
        }
    }
}
