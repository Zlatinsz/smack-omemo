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

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.jivesoftware.smack.SmackException;
import org.jivesoftware.smack.StanzaListener;
import org.jivesoftware.smack.XMPPException;
import org.jivesoftware.smack.filter.StanzaFilter;
import org.jivesoftware.smack.packet.ExtensionElement;
import org.jivesoftware.smack.packet.Message;
import org.jivesoftware.smack.packet.Stanza;
import org.jivesoftware.smack.util.StringUtils;
import org.jivesoftware.smackx.carbons.CarbonCopyReceivedListener;
import org.jivesoftware.smackx.carbons.CarbonManager;
import org.jivesoftware.smackx.carbons.packet.CarbonExtension;
import org.jivesoftware.smackx.disco.ServiceDiscoveryManager;
import org.jivesoftware.smackx.forward.packet.Forwarded;
import org.jivesoftware.smackx.mam.MamManager;
import org.jivesoftware.smackx.muc.MultiUserChat;
import org.jivesoftware.smackx.muc.MultiUserChatManager;
import org.jivesoftware.smackx.omemo.elements.OmemoBundleElement;
import org.jivesoftware.smackx.omemo.elements.OmemoDeviceListElement;
import org.jivesoftware.smackx.omemo.elements.OmemoMessageElement;
import org.jivesoftware.smackx.omemo.exceptions.CannotEstablishOmemoSessionException;
import org.jivesoftware.smackx.omemo.exceptions.CryptoFailedException;
import org.jivesoftware.smackx.omemo.exceptions.CorruptedOmemoKeyException;
import org.jivesoftware.smackx.omemo.exceptions.UndecidedOmemoIdentityException;
import org.jivesoftware.smackx.omemo.internal.CachedDeviceList;
import org.jivesoftware.smackx.omemo.internal.OmemoDevice;
import org.jivesoftware.smackx.omemo.internal.OmemoMessageInformation;
import org.jivesoftware.smackx.omemo.internal.OmemoSession;
import org.jivesoftware.smackx.omemo.listener.OmemoMessageListener;
import org.jivesoftware.smackx.omemo.listener.OmemoMucMessageListener;
import org.jivesoftware.smackx.omemo.internal.ClearTextMessage;
import org.jivesoftware.smackx.omemo.util.OmemoConstants;
import org.jivesoftware.smackx.omemo.util.OmemoMessageBuilder;
import org.jivesoftware.smackx.omemo.util.PubSubHelper;
import org.jivesoftware.smackx.pep.PEPListener;
import org.jivesoftware.smackx.pep.PEPManager;
import org.jivesoftware.smackx.pubsub.EventElement;
import org.jivesoftware.smackx.pubsub.ItemsExtension;
import org.jivesoftware.smackx.pubsub.LeafNode;
import org.jivesoftware.smackx.pubsub.PayloadItem;
import org.jivesoftware.smackx.pubsub.PubSubManager;
import org.jxmpp.jid.BareJid;
import org.jxmpp.jid.EntityBareJid;
import org.jxmpp.jid.Jid;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Random;
import java.util.logging.Level;
import java.util.logging.Logger;

import static org.jivesoftware.smackx.omemo.util.OmemoConstants.Encrypted.ENCRYPTED;
import static org.jivesoftware.smackx.omemo.util.OmemoConstants.MAX_INACTIVE_DEVICE_AGE_HOURS;
import static org.jivesoftware.smackx.omemo.util.OmemoConstants.PEP_NODE_DEVICE_LIST_NOTIFY;
import static org.jivesoftware.smackx.omemo.util.OmemoConstants.PEP_NODE_DEVICE_LIST;
import static org.jivesoftware.smackx.omemo.util.OmemoConstants.PEP_NODE_BUNDLE_FROM_DEVICE_ID;
import static org.jivesoftware.smackx.omemo.util.OmemoConstants.OMEMO_NAMESPACE;

/**
 * This class contains OMEMO related logic and registers listeners etc.
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
public abstract class OmemoService<T_IdKeyPair, T_IdKey, T_PreKey, T_SigPreKey, T_Sess, T_Addr, T_ECPub, T_Bundle, T_Ciph> {
    protected static final Logger LOGGER = Logger.getLogger(OmemoService.class.getName());
    protected final PubSubHelper pubSubHelper;

    protected LeafNode ownDeviceListNode;
    protected final OmemoManager omemoManager;
    protected final OmemoStore<T_IdKeyPair, T_IdKey, T_PreKey, T_SigPreKey, T_Sess, T_Addr, T_ECPub, T_Bundle, T_Ciph> omemoStore;

    private final HashSet<OmemoMessageListener<T_IdKey>> omemoMessageListeners = new HashSet<>();
    private final HashSet<OmemoMucMessageListener<T_IdKey>> omemoMucMessageListeners = new HashSet<>();

    protected final BareJid ownJid;

    /**
     * Create a new OmemoService object. This should only happen once.
     * When the service gets created, it tries a placeholder crypto function in order to test, if all necessary
     * algorithms are available on the system.
     *
     * @param manager The OmemoManager we want to provide this service to
     * @param store   The OmemoStore implementation that holds the key material
     * @throws NoSuchPaddingException               When no Cipher could be instantiated.
     * @throws NoSuchAlgorithmException             when no Cipher could be instantiated.
     * @throws NoSuchProviderException              when BouncyCastle could not be found.
     * @throws InvalidAlgorithmParameterException   when the Cipher could not be initialized
     * @throws InvalidKeyException                  when the generated key is invalid
     * @throws UnsupportedEncodingException         when UTF8 is unavailable
     * @throws BadPaddingException                  when cipher.doFinal gets wrong padding
     * @throws IllegalBlockSizeException            when cipher.doFinal gets wrong Block size.
     * @throws InterruptedException                 when we get interrupted
     * @throws CorruptedOmemoKeyException             when an OMEMO key is invalid
     * @throws XMPPException.XMPPErrorException     when an XMPP error occurs
     * @throws SmackException.NotConnectedException when we are/get disconnected
     * @throws SmackException.NoResponseException   when we get no response
     */
    public OmemoService(OmemoManager manager,
                        OmemoStore<T_IdKeyPair, T_IdKey, T_PreKey, T_SigPreKey, T_Sess, T_Addr, T_ECPub, T_Bundle, T_Ciph> store)
            throws NoSuchPaddingException, InvalidKeyException, UnsupportedEncodingException, IllegalBlockSizeException,
            BadPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException,
            InterruptedException, CorruptedOmemoKeyException, XMPPException.XMPPErrorException,
            SmackException.NotConnectedException, SmackException.NoResponseException {
        Security.addProvider(new BouncyCastleProvider());
        //Check availability of algorithms and encodings needed for crypto
        checkAvailableAlgorithms();

        this.omemoManager = manager;
        this.omemoStore = store;
        store.setOmemoService(this); //Tell the store about us
        this.ownJid = manager.getConnection().getUser().asBareJid();
        this.pubSubHelper = new PubSubHelper(manager);
        if (getOmemoStore().isFreshInstallation()) {
            LOGGER.log(Level.INFO, "No key material found. Looks like we have a fresh installation.");
            //Create new key material and publish it to the server
            publishInformationIfNeeded(true, false);
        } else {
            publishDeviceIdIfNeeded(false);
        }
        subscribeToDeviceLists();
        registerOmemoMessageStanzaListeners();  //Wait for new OMEMO messages
        omemoStore.initializeOmemoSessions();   //Preload existing OMEMO sessions
        omemoManager.setOmemoService(this);     //Let the manager know we are ready
    }

    protected void checkAvailableAlgorithms() throws NoSuchPaddingException, UnsupportedEncodingException,
            InvalidAlgorithmParameterException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException,
            NoSuchProviderException, InvalidKeyException {
        //Test crypto functions
        new OmemoMessageBuilder<>(getOmemoStore(), "");
        //Test encoding
        byte[] b = "".getBytes(StringUtils.UTF8);
    }

    /**
     * Get our latest deviceListNode from the server.
     * This method is used to prevent us from getting our node too often (it may take some time).
     */
    private LeafNode fetchDeviceListNode() throws SmackException.NotConnectedException, InterruptedException,
            SmackException.NoResponseException, XMPPException.XMPPErrorException {
        return PubSubManager.getInstance(omemoManager.getConnection(), ownJid).getOrCreateLeafNode(PEP_NODE_DEVICE_LIST);
    }

    /**
     * Publish our deviceId and a fresh bundle to the server.
     *
     * @param regenerate         Do we want to generate a new Identity?
     * @param deleteOtherDevices Do we want to delete other devices from our deviceList?
     */
    void publishInformationIfNeeded(boolean regenerate, boolean deleteOtherDevices) throws InterruptedException,
            XMPPException.XMPPErrorException, SmackException.NotConnectedException, SmackException.NoResponseException,
            CorruptedOmemoKeyException {
        if (regenerate) {
            regenerate();
        }
        publishDeviceIdIfNeeded(deleteOtherDevices);
        publishBundle();
    }

    /**
     * Generate a new unique deviceId and regenerate new keys.
     *
     * @throws CorruptedOmemoKeyException when freshly generated identityKey is invalid
     *                                  (should never ever happen *crosses fingers*)
     */
    private void regenerate() throws CorruptedOmemoKeyException {
        //Generate unique ID that is not already taken
        int deviceIdCandidate;
        do {
            deviceIdCandidate = omemoStore.generateOmemoDeviceId();
        } while (!omemoStore.isAvailableDeviceId(deviceIdCandidate));

        omemoStore.storeOmemoDeviceId(deviceIdCandidate);
        omemoStore.regenerate();
    }

    /**
     * Publish a fresh bundle to the server.
     */
    private void publishBundle()
            throws SmackException.NotConnectedException, InterruptedException,
            SmackException.NoResponseException, CorruptedOmemoKeyException, XMPPException.XMPPErrorException {
        LeafNode bundleNode = PubSubManager.getInstance(omemoManager.getConnection(), ownJid)
                .getOrCreateLeafNode(PEP_NODE_BUNDLE_FROM_DEVICE_ID(omemoStore.loadOmemoDeviceId()));
        bundleNode.send(new PayloadItem<>(omemoStore.packOmemoBundle()));
    }

    /**
     * Publish our deviceId in case it is not on the list already.
     *
     * @param deleteOtherDevices Do we want to remove other devices from the list?
     *                           If we do, publish the list with only our id, regardless if we were on the list
     *                           already.
     */
    private void publishDeviceIdIfNeeded(boolean deleteOtherDevices)
            throws SmackException.NotConnectedException, InterruptedException, SmackException.NoResponseException,
            XMPPException.XMPPErrorException {
        boolean publish = false;
        this.ownDeviceListNode = fetchDeviceListNode();
        OmemoDeviceListElement deviceList = getPubSubHelper().extractDeviceListFrom(ownDeviceListNode);

        if (deviceList == null) {
            deviceList = new OmemoDeviceListElement();
        }

        if (deleteOtherDevices) {
            deviceList.clear();
        }

        int ourDeviceId = omemoStore.loadOmemoDeviceId();
        if (!deviceList.contains(ourDeviceId)) {
            deviceList.add(ourDeviceId);
            publish = true;
        }

        //Clear devices that we didn't receive a message from for a while
        Iterator<Integer> it = deviceList.iterator();
        while(it.hasNext()) {
            int id = it.next();
            if(id == ourDeviceId) {
                //Skip own id
                continue;
            }
            OmemoDevice d = new OmemoDevice(ownJid, id);
            Date date = omemoStore.getDateOfLastReceivedMessage(d);
            if(date == null) {
                date = new Date();
                omemoStore.setDateOfLastReceivedMessage(d, date);
            }
            if(new Date().getTime() - date.getTime() > 1000 * 60 * 60 * MAX_INACTIVE_DEVICE_AGE_HOURS) {
                LOGGER.log(Level.INFO, "Remove device "+id+" because of more than " +
                        MAX_INACTIVE_DEVICE_AGE_HOURS+ " hours of inactivity.");
                it.remove();
                publish = true;
            }
        }

        if(publish) {
            publishDeviceIds(deviceList);
        }
    }

    /**
     * Publish the given deviceList to the server.
     *
     * @param deviceList list of deviceIDs
     * @throws InterruptedException                 Exception
     * @throws XMPPException.XMPPErrorException     Exception
     * @throws SmackException.NotConnectedException Exception
     * @throws SmackException.NoResponseException   Exception
     */
    protected void publishDeviceIds(OmemoDeviceListElement deviceList)
            throws InterruptedException, XMPPException.XMPPErrorException,
            SmackException.NotConnectedException, SmackException.NoResponseException {
        PubSubManager.getInstance(omemoManager.getConnection(),ownJid).getOrCreateLeafNode(OmemoConstants.PEP_NODE_DEVICE_LIST)
                .send(new PayloadItem<>(deviceList));
    }

    /**
     * Subscribe to the device lists of our contacts using PEP.
     */
    private void subscribeToDeviceLists() {
        registerDeviceListListener();
        ServiceDiscoveryManager.getInstanceFor(omemoManager.getConnection()).addFeature(PEP_NODE_DEVICE_LIST_NOTIFY);
    }

    /**
     * Build sessions for all devices of the contact that we do not have a session with yet.
     *
     * @param jid the BareJid of the contact
     */
    private void buildSessionsFromOmemoBundles(BareJid jid) {
        CachedDeviceList devices = omemoStore.loadCachedDeviceList(jid);
        if (devices == null) {
            try {
                omemoStore.mergeCachedDeviceList(jid, pubSubHelper.fetchDeviceList(jid));
            } catch (XMPPException.XMPPErrorException | SmackException.NotConnectedException | InterruptedException | SmackException.NoResponseException e) {
                LOGGER.log(Level.WARNING, e.getMessage());
            }
        }
        devices = omemoStore.loadCachedDeviceList(jid);
        if (devices == null) {
            return;
        }

        for (int id : devices.getActiveDevices()) {
            OmemoDevice device = new OmemoDevice(jid, id);
            if (omemoStore.getOmemoSessionOf(device) == null) {
                //Build missing session
                try {
                    buildSessionFromOmemoBundle(device);
                } catch (CannotEstablishOmemoSessionException | CorruptedOmemoKeyException e) {
                    LOGGER.log(Level.WARNING, e.getMessage());
                    //Skip
                }
            }
        }
    }

    /**
     * Build an OmemoSession for the given OmemoDevice.
     *
     * @param device OmemoDevice
     * @throws CannotEstablishOmemoSessionException when no session could be established
     * @throws CorruptedOmemoKeyException when the bundle contained an invalid OMEMO identityKey
     */
    public void buildSessionFromOmemoBundle(OmemoDevice device) throws CannotEstablishOmemoSessionException, CorruptedOmemoKeyException {
        if (device.equals(new OmemoDevice(ownJid, omemoStore.loadOmemoDeviceId()))) {
            LOGGER.log(Level.WARNING, "Do not build a session with yourself!");
            return;
        }
        OmemoBundleElement bundle;
        try {
            bundle = pubSubHelper.fetchBundle(device);
        } catch (SmackException | XMPPException.XMPPErrorException | InterruptedException e) {
            LOGGER.log(Level.WARNING, e.getMessage());
            throw new CannotEstablishOmemoSessionException("Can't build Session for " + device);
        }
        HashMap<Integer, T_Bundle> bundles;
        bundles = getOmemoStore().keyUtil().BUNDLE.bundles(bundle, device);
        int randomIndex = new Random().nextInt(bundles.size());
        T_Bundle randomPreKeyBundle = new ArrayList<>(bundles.values()).get(randomIndex);
        processBundle(randomPreKeyBundle, device);
    }

    /**
     * Process a received bundle. Typically that includes saving keys and building a session.
     *
     * @param bundle T_Bundle (depends on used Signal/Olm library)
     * @param device OmemoDevice
     */
    protected abstract void processBundle(T_Bundle bundle, OmemoDevice device) throws CorruptedOmemoKeyException;

    /**
     * Register a PEPListener that listens for deviceList updates.
     */
    private void registerDeviceListListener() {
        PEPManager.getInstanceFor(omemoManager.getConnection()).addPEPListener(new PEPListener() {
            @Override
            public void eventReceived(EntityBareJid from, EventElement event, Message message) {
                for (ExtensionElement items : event.getExtensions()) {
                    if (items instanceof ItemsExtension) {
                        for (ExtensionElement item : ((ItemsExtension) items).getItems()) {
                            if (item instanceof PayloadItem<?>) {
                                PayloadItem<?> payloadItem = (PayloadItem<?>) item;
                                //Device List <list>
                                if (payloadItem.getPayload() instanceof OmemoDeviceListElement) {
                                    OmemoDeviceListElement omemoDeviceListElement = (OmemoDeviceListElement) payloadItem.getPayload();
                                    int ourDeviceId = omemoStore.loadOmemoDeviceId();
                                    omemoStore.mergeCachedDeviceList(from, omemoDeviceListElement);
                                    if (from != null && from.equals(ownJid) && !omemoDeviceListElement.contains(ourDeviceId)) {
                                        //Our deviceId was not in our list!
                                        LOGGER.log(Level.INFO, "Device Id was not on the list!");
                                        omemoDeviceListElement.add(ourDeviceId);
                                        try {
                                            publishDeviceIds(omemoDeviceListElement);
                                        } catch (SmackException | InterruptedException | XMPPException.XMPPErrorException e) {
                                            //TODO: It might be dangerous NOT to retry publishing our deviceId
                                            LOGGER.log(Level.SEVERE, e.getMessage());
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        });
    }

    /**
     * Process a received message. Try to decrypt it in case we are a recipient device. If we are not a recipient
     * device, return null.
     *
     * @param sender  the BareJid of the sender of the message
     * @param message the encrypted message
     * @return decrypted message or null
     */
    private Message processReceivingMessage(BareJid sender, OmemoMessageElement message, final OmemoMessageInformation<T_IdKey> information)
            throws InterruptedException, SmackException.NoResponseException, SmackException.NotConnectedException,
            CryptoFailedException, XMPPException.XMPPErrorException, CorruptedOmemoKeyException {
        ArrayList<OmemoMessageElement.OmemoHeader.Key> messageRecipientKeys = message.getHeader().getKeys();
        //Do we have a key with our ID in the message?
        for (OmemoMessageElement.OmemoHeader.Key k : messageRecipientKeys) {
            if (k.getId() == omemoStore.loadOmemoDeviceId()) {
                OmemoDevice d = new OmemoDevice(sender, message.getHeader().getSid());
                Message decrypted = decryptOmemoMessageElement(d, message, information);
                if(sender.equals(ownJid) && decrypted != null) {
                    omemoStore.setDateOfLastReceivedMessage(d);
                }
                return decrypted;
            }
        }
        LOGGER.log(Level.INFO, "There is no key with our deviceId. Silently discard the message.");
        return null;
    }

    /**
     * Decrypt a given OMEMO encrypted message. Return null, if there is no OMEMO element in the message,
     * otherwise try to decrypt the message and return a ClearTextMessage object.
     * @param sender barejid of the sender
     * @param message encrypted message
     * @return decrypted message or null
     * @throws InterruptedException                 Exception
     * @throws SmackException.NoResponseException   Exception
     * @throws SmackException.NotConnectedException Exception
     * @throws CryptoFailedException                When the message could not be decrypted.
     * @throws XMPPException.XMPPErrorException     Exception
     * @throws CorruptedOmemoKeyException             When the used OMEMO keys are invalid.
     */
    ClearTextMessage<T_IdKey> processLocalMessage(BareJid sender, Message message) throws InterruptedException, SmackException.NoResponseException, SmackException.NotConnectedException, CryptoFailedException, XMPPException.XMPPErrorException, CorruptedOmemoKeyException {
        if(OmemoManager.stanzaContainsOmemoMessage(message)) {
            OmemoMessageElement omemoMessageElement = message.getExtension(OmemoConstants.Encrypted.ENCRYPTED, OMEMO_NAMESPACE);
            OmemoMessageInformation<T_IdKey> info = new OmemoMessageInformation<>();
            Message decrypted = processReceivingMessage(sender, omemoMessageElement, info);
            return new ClearTextMessage<>(decrypted != null ? decrypted.getBody() : null, message, info);
        } else {
            LOGGER.log(Level.WARNING, "Stanza does not contain an OMEMO message.");
            return null;
        }
    }

    /**
     * Encrypt a clear text message for the given recipient.
     * The body of the message will be encrypted.
     *
     * @param recipient BareJid of the recipient
     * @param message   message to encrypt.
     * @return OmemoMessageElement
     */
    OmemoMessageElement processSendingMessage(BareJid recipient, Message message)
            throws CryptoFailedException, UndecidedOmemoIdentityException, NoSuchAlgorithmException {
        ArrayList<BareJid> recipients = new ArrayList<>();
        recipients.add(recipient);
        return processSendingMessage(recipients, message);
    }

    /**
     * Encrypt a clear text message for the given recipients.
     * The body of the message will be encrypted.
     *
     * @param recipients List of BareJids of all recipients
     * @param message    message to encrypt.
     * @return OmemoMessageElement
     */
    OmemoMessageElement processSendingMessage(List<BareJid> recipients, Message message)
            throws CryptoFailedException, UndecidedOmemoIdentityException, NoSuchAlgorithmException {
        //Them - The contact wants to read the message on all their devices.
        //Fetch a fresh list in case we had none before.
        List<OmemoDevice> receivers = new ArrayList<>();
        for (BareJid recipient : recipients) {
            if (recipient.equals(ownJid)) {
                //Skip our jid
                continue;
            }
            buildSessionsFromOmemoBundles(recipient);
            CachedDeviceList theirDevices = omemoStore.loadCachedDeviceList(recipient);
            for (int id : theirDevices.getActiveDevices()) {
                receivers.add(new OmemoDevice(recipient, id));
            }
        }

        //TODO: What if the recipients list does not exist/not contain any of their keys (they do not support OMEMO)?

        //Us - We want to read the message on all of our devices
        CachedDeviceList ourDevices = omemoStore.loadCachedDeviceList(ownJid);
        if (ourDevices == null) {
            ourDevices = new CachedDeviceList();
        }
        for (int id : ourDevices.getActiveDevices()) {
            if (id != omemoStore.loadOmemoDeviceId()) {
                receivers.add(new OmemoDevice(ownJid, id));
            }
        }

        return encryptOmemoMessage(receivers, message);
    }

    /**
     * Decrypt a incoming OmemoMessageElement that was sent by the OmemoDevice 'from'.
     *
     * @param from    OmemoDevice that sent the message
     * @param message Encrypted OmemoMessageElement
     * @return Decrypted message
     * @throws CryptoFailedException when decrypting message fails for some reason
     */
    private Message decryptOmemoMessageElement(OmemoDevice from, OmemoMessageElement message, final OmemoMessageInformation<T_IdKey> information)
            throws CryptoFailedException, InterruptedException, CorruptedOmemoKeyException, XMPPException.XMPPErrorException,
            SmackException.NotConnectedException, SmackException.NoResponseException {
        int preKeyCountBefore = getOmemoStore().loadOmemoPreKeys().size();
        Message decrypted;

        //Get the session that will decrypt the message. If we have no such session, create a new one.
        OmemoSession<T_IdKeyPair, T_IdKey, T_PreKey, T_SigPreKey, T_Sess, T_Addr, T_ECPub, T_Bundle, T_Ciph> session = omemoStore.getOmemoSessionOf(from);
        if (session != null) {
            decrypted = message.decrypt(session, omemoStore.loadOmemoDeviceId());
        } else {
            session = createSession(from);
            decrypted = message.decrypt(session, omemoStore.loadOmemoDeviceId());
        }

        information.setSenderDevice(from);
        information.setSenderIdentityKey(session.getIdentityKey());

        // Check, if we use up a preKey (the message was a PreKeyMessage)
        // If we did, republish a bundle with the used keys replaced with fresh keys
        // TODO: Do this AFTER returning the message?
        if (getOmemoStore().loadOmemoPreKeys().size() != preKeyCountBefore) {
            LOGGER.log(Level.INFO, "We used up a preKey. Publish new Bundle.");
            publishBundle();
        }
        return decrypted;
    }

    /**
     * Encrypt the message and return it as an OmemoMessageElement.
     *
     * @param recipients List of devices that will be able to decipher the message.
     * @param message   Clear text message
     *
     * @throws CryptoFailedException when some cryptographic function fails
     * @throws UndecidedOmemoIdentityException when the identity of one or more contacts is undecided
     *
     * @return OmemoMessageElement
     */
    private OmemoMessageElement encryptOmemoMessage(List<OmemoDevice> recipients, Message message)
            throws CryptoFailedException, UndecidedOmemoIdentityException {
        OmemoMessageBuilder<T_IdKeyPair, T_IdKey, T_PreKey, T_SigPreKey, T_Sess, T_Addr, T_ECPub, T_Bundle, T_Ciph>
                builder;
        try {
            builder = new OmemoMessageBuilder<>(omemoStore, message.getBody());
        } catch (UnsupportedEncodingException | BadPaddingException | IllegalBlockSizeException | NoSuchProviderException |
                NoSuchPaddingException | InvalidAlgorithmParameterException | InvalidKeyException | NoSuchAlgorithmException e) {
            throw new CryptoFailedException(e);
        }

        UndecidedOmemoIdentityException undecided = null;

        for (OmemoDevice c : recipients) {
            try {
                builder.addRecipient(c);
            } catch (CannotEstablishOmemoSessionException | CorruptedOmemoKeyException e) {
                //TODO: How to react?
                LOGGER.log(Level.SEVERE, e.getMessage());
            } catch (UndecidedOmemoIdentityException e) {
                //Collect all undecided devices
                if (undecided == null) {
                    undecided = e;
                } else {
                    undecided.join(e);
                }
            }
        }

        if (undecided != null) {
            throw undecided;
        }
        return builder.finish();
    }

    /**
     * Create a new crypto-specific Session object.
     *
     * @param from the device we want to create the session with.
     * @return a new session
     */
    protected abstract OmemoSession<T_IdKeyPair, T_IdKey, T_PreKey, T_SigPreKey, T_Sess, T_Addr, T_ECPub, T_Bundle, T_Ciph>
    createSession(OmemoDevice from);

    /**
     * Return our OmemoStore.
     *
     * @return our store
     */
    OmemoStore<T_IdKeyPair, T_IdKey, T_PreKey, T_SigPreKey, T_Sess, T_Addr, T_ECPub, T_Bundle, T_Ciph>
    getOmemoStore() {
        return this.omemoStore;
    }

    /**
     * Return our PubSubHelper.
     *
     * @return PubSubHelper
     */
    public PubSubHelper getPubSubHelper() {
        return this.pubSubHelper;
    }

    /**
     * Listen for incoming messages and carbons, decrypt them and pass the cleartext messages to the registered
     * OmemoMessageListeners.
     */
    private void registerOmemoMessageStanzaListeners() {
        omemoManager.getConnection().addAsyncStanzaListener(omemoMessageListener, omemoMessageFilter);
        //Carbons
        CarbonManager.getInstanceFor(omemoManager.getConnection())
                .addCarbonCopyReceivedListener(omemoCarbonMessageListener);
    }

    /**
     * StanzaFilter that filters messages containing a OMEMO message element.
     */
    private final StanzaFilter omemoMessageFilter = new StanzaFilter() {
        @Override
        public boolean accept(Stanza stanza) {
            return stanza instanceof Message && OmemoManager.stanzaContainsOmemoMessage(stanza);
        }
    };

    /**
     * StanzaListener that listens for incoming OMEMO messages.
     */
    private final StanzaListener omemoMessageListener = new StanzaListener() {
        @Override
        public void processStanza(Stanza packet) throws SmackException.NotConnectedException, InterruptedException {
            Message decrypted;
            OmemoMessageInformation<T_IdKey> messageInfo = new OmemoMessageInformation<>();
            Jid sender = packet.getFrom();
            MultiUserChatManager mucm = MultiUserChatManager.getInstanceFor(omemoManager.getConnection());
            //Is it a MUC message...
            if (mucm.getJoinedRooms().contains(sender.asBareJid().asEntityBareJidIfPossible())) {
                MultiUserChat muc = mucm.getMultiUserChat(sender.asEntityBareJidIfPossible());
                BareJid senderContact = muc.getOccupant(sender.asEntityFullJidIfPossible()).getJid().asBareJid();
                try {
                    decrypted = processReceivingMessage(senderContact, (OmemoMessageElement) packet.getExtension(ENCRYPTED, OMEMO_NAMESPACE), messageInfo);
                    if (decrypted != null) {
                        notifyOmemoMucMessageReceived(muc, senderContact, decrypted.getBody(), (Message) packet, null, messageInfo);
                    }
                } catch (SmackException.NoResponseException | CorruptedOmemoKeyException | XMPPException.XMPPErrorException | CryptoFailedException e) {
                    LOGGER.log(Level.WARNING, e.getMessage());
                }
            }

            //... or a normal chat message...
            else {
                try {
                    decrypted = processReceivingMessage(
                            packet.getFrom().asBareJid(),
                            (OmemoMessageElement) packet.getExtension(ENCRYPTED, OMEMO_NAMESPACE), messageInfo);
                    if (decrypted != null) {
                        notifyOmemoMessageReceived(decrypted.getBody(), (Message) packet, null, messageInfo);
                    }
                } catch (SmackException.NoResponseException | CorruptedOmemoKeyException | XMPPException.XMPPErrorException | CryptoFailedException e) {
                    LOGGER.log(Level.WARNING, e.getMessage());
                }
            }
        }
    };

    /**
     * CarbonCopyListener that listens for incoming OMEMO message carbon copies.
     */
    private final CarbonCopyReceivedListener omemoCarbonMessageListener = new CarbonCopyReceivedListener() {
        @Override
        public void onCarbonCopyReceived(CarbonExtension.Direction direction, Message carbonCopy, Message wrappingMessage) {
            if (omemoMessageFilter.accept(carbonCopy)) {
                Message decrypted;
                MultiUserChatManager mucm = MultiUserChatManager.getInstanceFor(omemoManager.getConnection());
                OmemoMessageInformation<T_IdKey> messageInfo = new OmemoMessageInformation<>();
                if (CarbonExtension.Direction.received.equals(direction)) {
                    messageInfo.setCarbon(OmemoMessageInformation.CARBON.RECV);
                } else {
                    messageInfo.setCarbon(OmemoMessageInformation.CARBON.SENT);
                }

                BareJid sender = getSenderBareJidFromMucMessage(carbonCopy);
                //Is it a MUC message...
                if (sender != null) {
                    MultiUserChat muc = mucm.getMultiUserChat(carbonCopy.getFrom().asEntityBareJidIfPossible());
                    try {
                        decrypted = processReceivingMessage(sender, (OmemoMessageElement) carbonCopy.getExtension(ENCRYPTED, OMEMO_NAMESPACE), messageInfo);
                        if (decrypted != null) {
                            notifyOmemoMucMessageReceived(muc, sender, decrypted.getBody(), carbonCopy, wrappingMessage, messageInfo);
                        }
                    } catch (CryptoFailedException | CorruptedOmemoKeyException | InterruptedException | SmackException.NotConnectedException | XMPPException.XMPPErrorException | SmackException.NoResponseException e) {
                        LOGGER.log(Level.WARNING, e.getMessage());
                    }
                }

                //... or a normal chat message...
                else {
                    sender = carbonCopy.getFrom().asBareJid();
                    try {
                        decrypted = processReceivingMessage(sender, (OmemoMessageElement) carbonCopy.getExtension(ENCRYPTED, OMEMO_NAMESPACE), messageInfo);
                        if (decrypted != null) {
                            notifyOmemoMessageReceived(decrypted.getBody(), carbonCopy, wrappingMessage, messageInfo);
                        }
                    } catch (CryptoFailedException | CorruptedOmemoKeyException | InterruptedException | SmackException.NotConnectedException | XMPPException.XMPPErrorException | SmackException.NoResponseException e) {
                        LOGGER.log(Level.WARNING, e.getMessage());
                    }
                }
            }
        }
    };

    public List<ClearTextMessage<T_IdKey>> decryptMamQueryResult(MamManager.MamQueryResult mamQueryResult)
            throws InterruptedException, XMPPException.XMPPErrorException, SmackException.NotConnectedException, SmackException.NoResponseException {
        List<ClearTextMessage<T_IdKey>> result = new ArrayList<>();
        for(Forwarded f : mamQueryResult.forwardedMessages) {
            if(OmemoManager.stanzaContainsOmemoMessage(f.getForwardedStanza())) {
                //Decrypt OMEMO messages
                try {
                    result.add(processLocalMessage(f.getForwardedStanza().getFrom().asBareJid(), (Message) f.getForwardedStanza()));
                } catch (CorruptedOmemoKeyException | CryptoFailedException e) {
                    LOGGER.log(Level.WARNING, e.getMessage());
                }
            } else {
                //Wrap cleartext messages
                Message m = (Message) f.getForwardedStanza();
                result.add(new ClearTextMessage<>(m.getBody(), m,
                        new OmemoMessageInformation<T_IdKey>(null, null, OmemoMessageInformation.CARBON.NONE, false)));
            }
        }
        return result;
    }

    /**
     * Add an OmemoMessageListener, which the client can use to get updated when OmemoMessages are received in normal chat
     * sessions.
     *
     * @param listener OmemoMessageListener
     */
    @SuppressWarnings("unused")
    public void addOmemoMessageListener(OmemoMessageListener<T_IdKey> listener) {
        this.omemoMessageListeners.add(listener);
    }

    /**
     * Add an OmemoMucMessageListener, which the client can use to get updated when an OmemoMessageElement is received in a
     * MUC.
     *
     * @param listener OmemoMucMessageListener
     */
    @SuppressWarnings("unused")
    public void addOmemoMucMessageListener(OmemoMucMessageListener<T_IdKey> listener) {
        this.omemoMucMessageListeners.add(listener);
    }

    /**
     * Remove an OmemoMessageListener.
     *
     * @param listener OmemoMessageListener
     */
    @SuppressWarnings("unused")
    public void removeOmemoMessageListener(OmemoMessageListener<T_IdKey> listener) {
        this.omemoMessageListeners.remove(listener);
    }

    /**
     * Remove an OmemoMucMessageListener.
     *
     * @param listener OmemoMucMessageListener
     */
    @SuppressWarnings("unused")
    public void removeOmemoMucMessageListener(OmemoMucMessageListener<T_IdKey> listener) {
        this.omemoMucMessageListeners.remove(listener);
    }

    /**
     * Notify all registered OmemoMessageListeners about a received OmemoMessage.
     *
     * @param decryptedBody      decrypted Body element of the message
     * @param encryptedMessage   unmodified message as it was received
     * @param messageInformation information about the messages encryption (used identityKey, carbon...)
     */
    private void notifyOmemoMessageReceived(String decryptedBody, Message encryptedMessage, Message wrappingMessage, OmemoMessageInformation<T_IdKey> messageInformation) {
        for (OmemoMessageListener<T_IdKey> l : omemoMessageListeners) {
            l.onOmemoMessageReceived(decryptedBody, encryptedMessage, wrappingMessage, messageInformation);
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
    private void notifyOmemoMucMessageReceived(MultiUserChat muc, BareJid from, String decryptedBody, Message message,
                                               Message wrappingMessage, OmemoMessageInformation<T_IdKey> omemoInformation) {
        for (OmemoMucMessageListener<T_IdKey> l : omemoMucMessageListeners) {
            l.onOmemoMucMessageReceived(muc, from, decryptedBody, message,
                    wrappingMessage, omemoInformation);
        }
    }

    /**
     * Return the barejid of the user that sent the message inside the MUC. If the message wasn't sent in a MUC,
     * return null;
     * @param stanza message
     * @return BareJid of the sender.
     */
    public BareJid getSenderBareJidFromMucMessage(Stanza stanza) {
        BareJid sender = stanza.getFrom().asBareJid();
        MultiUserChatManager mucm = MultiUserChatManager.getInstanceFor(omemoManager.getConnection());
        //MultiUserChat
        if(mucm.getJoinedRooms().contains(sender.asEntityBareJidIfPossible())) {
            MultiUserChat muc = mucm.getMultiUserChat(sender.asEntityBareJidIfPossible());
            return muc.getOccupant(sender.asEntityFullJidIfPossible()).getJid().asBareJid();
        }
        return null;
    }
}
