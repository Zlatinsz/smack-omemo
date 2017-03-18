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
package org.jivesoftware.smackx.omemo;

import org.jivesoftware.smack.Manager;
import org.jivesoftware.smack.SmackException;
import org.jivesoftware.smack.XMPPConnection;
import org.jivesoftware.smack.XMPPException;
import org.jivesoftware.smack.packet.Message;
import org.jivesoftware.smack.packet.StandardExtensionElement;
import org.jivesoftware.smackx.disco.ServiceDiscoveryManager;
import org.jivesoftware.smackx.muc.MultiUserChatManager;
import org.jivesoftware.smackx.muc.RoomInfo;
import org.jivesoftware.smackx.omemo.elements.OmemoMessageElement;
import org.jivesoftware.smackx.omemo.exceptions.CryptoFailedException;
import org.jivesoftware.smackx.omemo.exceptions.InvalidOmemoKeyException;
import org.jivesoftware.smackx.omemo.exceptions.UndecidedOmemoIdentityException;
import org.jivesoftware.smackx.pubsub.packet.PubSub;
import org.jxmpp.jid.BareJid;
import org.jxmpp.jid.DomainBareJid;
import org.jxmpp.jid.EntityBareJid;
import org.jxmpp.jid.Jid;

import java.security.NoSuchAlgorithmException;
import java.util.List;
import java.util.WeakHashMap;
import java.util.logging.Level;
import java.util.logging.Logger;

import static org.jivesoftware.smackx.omemo.util.OmemoConstants.BODY_OMEMO_HINT;
import static org.jivesoftware.smackx.omemo.util.OmemoConstants.OMEMO;
import static org.jivesoftware.smackx.omemo.util.OmemoConstants.OMEMO_NAMESPACE;
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
     */
    public void purgeDevices() throws SmackException, InterruptedException, XMPPException.XMPPErrorException, InvalidOmemoKeyException {
        service.publishInformationIfNeeded(false, true);
    }

    /**
     * Generate fresh identity keys and bundle and publish it to the server.
     */
    public void regenerate() throws SmackException, InterruptedException, XMPPException.XMPPErrorException, InvalidOmemoKeyException {
        //create a new identity and publish new keys to the server
        getOmemoService().publishInformationIfNeeded(true, false);
    }

    /**
     * OMEMO encrypt a cleartext message for a single recipient.
     *
     * @param to      Recipients BareJid
     * @param message Message that will be encrypted. The body of the message will be encrypted.
     * @return new a new Message with the encrypted message in the 'encrypted' element and a hint for
     * OMEMO-uncapable clients in the body
     */
    public Message encrypt(BareJid to, Message message) throws CryptoFailedException, UndecidedOmemoIdentityException, NoSuchAlgorithmException {
        OmemoMessageElement encrypted = service.processSendingMessage(to, message);
        return finishMessage(encrypted);
    }

    /**
     * OMEMO encrypt a cleartext message for multiple recipients.
     *
     * @param recipients Receipients BareJids
     * @param message    Message that will be encrypted. The body of the message will be encrypted.
     * @return new a new Message with the encrypted message in the 'encrypted' element and a hint for
     * OMEMO-incapable clients in the body
     */
    public Message encrypt(List<BareJid> recipients, Message message) throws CryptoFailedException, UndecidedOmemoIdentityException, NoSuchAlgorithmException {
        OmemoMessageElement encrypted = getOmemoService().processSendingMessage(recipients, message);
        return finishMessage(encrypted);
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
    private Message finishMessage(OmemoMessageElement encrypted) {
        if (encrypted != null) {
            Message chatMessage = new Message();
            chatMessage.setFrom(connection().getUser().asBareJid());
            chatMessage.addExtension(encrypted);
            chatMessage.setBody(BODY_OMEMO_HINT);

            //Tell server to store message despite possibly empty body
            chatMessage.addExtension(new StandardExtensionElement("store", "urn:xmpp:hints"));
            //Explicit Message Encryption
            StandardExtensionElement.Builder b = StandardExtensionElement.builder("encryption", "urn:xmpp:eme:0");
            b.addAttribute("name", OMEMO).addAttribute("namespace", OMEMO_NAMESPACE);
            chatMessage.addExtension(b.build());
            return chatMessage;
        }
        return null;
    }

    /**
     * Returns true, if the device resource has announced OMEMO support.
     *
     * @param resource jid of a resource
     * @return true if resource supports OMEMO
     * @throws XMPPException.XMPPErrorException     if
     * @throws SmackException.NotConnectedException something
     * @throws InterruptedException                 goes
     * @throws SmackException.NoResponseException   wrong
     */
    public boolean resourceSupportsOmemo(Jid resource) throws XMPPException.XMPPErrorException, SmackException.NotConnectedException, InterruptedException, SmackException.NoResponseException {
        return ServiceDiscoveryManager.getInstanceFor(connection()).discoverInfo(resource).containsFeature(PEP_NODE_DEVICE_LIST_NOTIFY);
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
     */
    public boolean serverSupportsOmemo(DomainBareJid server) throws XMPPException.XMPPErrorException, SmackException.NotConnectedException, InterruptedException, SmackException.NoResponseException {
        //TODO: Which is better?
        return ServiceDiscoveryManager.getInstanceFor(connection()).discoverInfo(server).containsFeature(PubSub.NAMESPACE);
        //return ServiceDiscoveryManager.getInstanceFor(connection()).discoverInfo(server).hasIdentity("pubsub", "pep");
    }

    /**
     * Return the fingerprint of our identity key.
     *
     * @return fingerprint
     */
    public String getOurFingerprint() {
        return getOmemoService().getOmemoStore().getFingerprint();
    }

    /**
     * Rotate the signedPreKey published in our OmemoBundle. This should be done every now and then (7-14 days).
     * The old signedPreKey should be kept for some more time (a month or so) to enable decryption of messages
     * that have been sent since the key was changed.
     *
     * @throws InvalidOmemoKeyException When the IdentityKeyPair is damaged.
     * @throws InterruptedException XMPP error
     * @throws XMPPException.XMPPErrorException XMPP error
     * @throws SmackException.NotConnectedException XMPP error
     * @throws SmackException.NoResponseException XMPP error
     */
    public void rotateSignedPreKey() throws InvalidOmemoKeyException, InterruptedException, XMPPException.XMPPErrorException, SmackException.NotConnectedException, SmackException.NoResponseException {
        //generate key
        getOmemoService().getOmemoStore().changeSignedPreKey();
        //publish
        getOmemoService().publishInformationIfNeeded(false, false);
        //TODO: delete old keys
    }
}
