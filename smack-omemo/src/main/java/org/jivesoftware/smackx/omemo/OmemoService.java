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

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.jivesoftware.smack.SmackException;
import org.jivesoftware.smack.StanzaListener;
import org.jivesoftware.smack.XMPPException;
import org.jivesoftware.smack.filter.StanzaFilter;
import org.jivesoftware.smack.packet.ExtensionElement;
import org.jivesoftware.smack.packet.Message;
import org.jivesoftware.smack.packet.Stanza;
import org.jivesoftware.smack.packet.XMPPError;
import org.jivesoftware.smackx.carbons.CarbonCopyReceivedListener;
import org.jivesoftware.smackx.carbons.CarbonManager;
import org.jivesoftware.smackx.carbons.packet.CarbonExtension;
import org.jivesoftware.smackx.disco.ServiceDiscoveryManager;
import org.jivesoftware.smackx.forward.packet.Forwarded;
import org.jivesoftware.smackx.mam.MamManager;
import org.jivesoftware.smackx.muc.MultiUserChat;
import org.jivesoftware.smackx.muc.MultiUserChatManager;
import org.jivesoftware.smackx.omemo.elements.OmemoBundleVAxolotlElement;
import org.jivesoftware.smackx.omemo.elements.OmemoDeviceListElement;
import org.jivesoftware.smackx.omemo.elements.OmemoDeviceListVAxolotlElement;
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
import org.jivesoftware.smackx.omemo.internal.IdentityKeyWrapper;
import org.jivesoftware.smackx.omemo.internal.OmemoDevice;
import org.jivesoftware.smackx.omemo.internal.OmemoMessageInformation;
import org.jivesoftware.smackx.omemo.internal.OmemoSession;
import org.jivesoftware.smackx.omemo.util.OmemoConstants;
import org.jivesoftware.smackx.omemo.util.OmemoMessageBuilder;
import org.jivesoftware.smackx.pep.PEPListener;
import org.jivesoftware.smackx.pep.PEPManager;
import org.jivesoftware.smackx.pubsub.EventElement;
import org.jivesoftware.smackx.pubsub.ItemsExtension;
import org.jivesoftware.smackx.pubsub.LeafNode;
import org.jivesoftware.smackx.pubsub.PayloadItem;
import org.jivesoftware.smackx.pubsub.PubSubAssertionError;
import org.jivesoftware.smackx.pubsub.PubSubException;
import org.jivesoftware.smackx.pubsub.PubSubManager;
import org.jxmpp.jid.BareJid;
import org.jxmpp.jid.EntityBareJid;

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
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Random;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

import static org.jivesoftware.smackx.omemo.util.OmemoConstants.OMEMO_NAMESPACE_V_AXOLOTL;
import static org.jivesoftware.smackx.omemo.util.OmemoConstants.PEP_NODE_BUNDLE_FROM_DEVICE_ID;
import static org.jivesoftware.smackx.omemo.util.OmemoConstants.PEP_NODE_DEVICE_LIST;
import static org.jivesoftware.smackx.omemo.util.OmemoConstants.PEP_NODE_DEVICE_LIST_NOTIFY;

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

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    protected static final Logger LOGGER = Logger.getLogger(OmemoService.class.getName());

    private static OmemoService<?, ?, ?, ?, ?, ?, ?, ?, ?> INSTANCE;

    protected OmemoStore<T_IdKeyPair, T_IdKey, T_PreKey, T_SigPreKey, T_Sess, T_Addr, T_ECPub, T_Bundle, T_Ciph> omemoStore;

    static OmemoService<?, ?, ?, ?, ?, ?, ?, ?, ?> getInstance() {
        if (INSTANCE == null) {
            throw new IllegalStateException("No OmemoService registered");
        }
        return INSTANCE;
    }

    protected static void setInstance(OmemoService<?, ?, ?, ?, ?, ?, ?, ?, ?> omemoService) {
        if (INSTANCE != null) {
            throw new IllegalStateException("An OmemoService is already registered");
        }
        INSTANCE = omemoService;
    }

    public OmemoStore<T_IdKeyPair, T_IdKey, T_PreKey, T_SigPreKey, T_Sess, T_Addr, T_ECPub, T_Bundle, T_Ciph>
    getOmemoStoreBackend() {
        if(omemoStore == null) {
            setOmemoStoreBackend(createDefaultOmemoStoreBackend());
            return getOmemoStoreBackend();
        }
        return omemoStore;
    }

    public void setOmemoStoreBackend(
            OmemoStore<T_IdKeyPair, T_IdKey, T_PreKey, T_SigPreKey, T_Sess, T_Addr, T_ECPub, T_Bundle, T_Ciph> omemoStore) {
        if(this.omemoStore != null) {
            throw new IllegalStateException("An OmemoStore backend has already been set.");
        }
        this.omemoStore = omemoStore;
    }

    public abstract OmemoStore<T_IdKeyPair, T_IdKey, T_PreKey, T_SigPreKey, T_Sess, T_Addr, T_ECPub, T_Bundle, T_Ciph>
    createDefaultOmemoStoreBackend();

    /**
     * Create a new OmemoService object. This should only happen once.
     * When the service gets created, it tries a placeholder crypto function in order to test, if all necessary
     * algorithms are available on the system.
     *
     * @throws NoSuchPaddingException               When no Cipher could be instantiated.
     * @throws NoSuchAlgorithmException             when no Cipher could be instantiated.
     * @throws NoSuchProviderException              when BouncyCastle could not be found.
     * @throws InvalidAlgorithmParameterException   when the Cipher could not be initialized
     * @throws InvalidKeyException                  when the generated key is invalid
     * @throws UnsupportedEncodingException         when UTF8 is unavailable
     * @throws BadPaddingException                  when cipher.doFinal gets wrong padding
     * @throws IllegalBlockSizeException            when cipher.doFinal gets wrong Block size.
     */
    public OmemoService()
            throws NoSuchPaddingException, InvalidKeyException, UnsupportedEncodingException, IllegalBlockSizeException,
            BadPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {

        //Check availability of algorithms and encodings needed for crypto
        checkAvailableAlgorithms();
    }

    /**
     * Initialize OMEMO functionality for OmemoManager omemoManager.
     *
     * @throws InterruptedException
     * @throws CorruptedOmemoKeyException
     * @throws XMPPException.XMPPErrorException
     * @throws SmackException.NotConnectedException
     * @throws SmackException.NoResponseException
     * @throws SmackException.NotLoggedInException
     * @throws PubSubException.NotALeafNodeException
     */
    void initialize(OmemoManager omemoManager) throws InterruptedException, CorruptedOmemoKeyException, XMPPException.XMPPErrorException, SmackException.NotConnectedException, SmackException.NoResponseException, SmackException.NotLoggedInException, PubSubException.NotALeafNodeException {
        if (!omemoManager.getConnection().isAuthenticated()) {
            throw new SmackException.NotLoggedInException();
        }

        boolean mustPublishId = false;
        if (getOmemoStoreBackend().isFreshInstallation(omemoManager)) {
            LOGGER.log(Level.INFO, "No key material found. Looks like we have a fresh installation.");
            //Create new key material and publish it to the server
            regenerate(omemoManager, omemoManager.getDeviceId());
            mustPublishId = true;
        }

        //Get fresh device list from server
        mustPublishId |= refreshOwnDeviceList(omemoManager);

        publishDeviceIdIfNeeded(omemoManager, false, mustPublishId);
        publishBundle(omemoManager);

        subscribeToDeviceLists(omemoManager);
        registerOmemoMessageStanzaListeners(omemoManager);  //Wait for new OMEMO messages
        getOmemoStoreBackend().initializeOmemoSessions(omemoManager);   //Preload existing OMEMO sessions
    }

    /**
     * Test availability of required algorithms. We do this in advance, so we can simplify exception handling later.
     *
     * @throws NoSuchPaddingException
     * @throws UnsupportedEncodingException
     * @throws InvalidAlgorithmParameterException
     * @throws NoSuchAlgorithmException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     * @throws NoSuchProviderException
     * @throws InvalidKeyException
     */
    protected void checkAvailableAlgorithms() throws NoSuchPaddingException, UnsupportedEncodingException,
            InvalidAlgorithmParameterException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException,
            NoSuchProviderException, InvalidKeyException {
        //Test crypto functions
        new OmemoMessageBuilder<>(null, null, "");
    }

    /**
     * Generate a new unique deviceId and regenerate new keys.
     *
     * @throws CorruptedOmemoKeyException when freshly generated identityKey is invalid
     *                                  (should never ever happen *crosses fingers*)
     */
    void regenerate(OmemoManager omemoManager, Integer nDeviceId) throws CorruptedOmemoKeyException {
        //Generate unique ID that is not already taken
        while (nDeviceId == null || !getOmemoStoreBackend().isAvailableDeviceId(omemoManager, nDeviceId)) {
            nDeviceId = OmemoManager.randomDeviceId();
        }

        getOmemoStoreBackend().forgetOmemoSessions(omemoManager);
        getOmemoStoreBackend().purgeOwnDeviceKeys(omemoManager);
        omemoManager.setDeviceId(nDeviceId);
        getOmemoStoreBackend().regenerate(omemoManager);
    }

    /**
     * Publish a fresh bundle to the server.
     * @throws SmackException.NotConnectedException
     * @throws InterruptedException
     * @throws SmackException.NoResponseException
     * @throws CorruptedOmemoKeyException
     * @throws XMPPException.XMPPErrorException
     */
    void publishBundle(OmemoManager omemoManager)
            throws SmackException.NotConnectedException, InterruptedException,
            SmackException.NoResponseException, CorruptedOmemoKeyException, XMPPException.XMPPErrorException {
        Date lastSignedPreKeyRenewal = getOmemoStoreBackend().getDateOfLastSignedPreKeyRenewal(omemoManager);
        if(OmemoConfiguration.getInstance().getRenewOldSignedPreKeys() && lastSignedPreKeyRenewal != null) {
            if(System.currentTimeMillis() - lastSignedPreKeyRenewal.getTime()
                    > 1000L * 60 * 60 * OmemoConfiguration.getInstance().getRenewOldSignedPreKeysAfterHours()) {
                LOGGER.log(Level.INFO, "Renewing signedPreKey");
                getOmemoStoreBackend().changeSignedPreKey(omemoManager);
            }
        } else {
            getOmemoStoreBackend().setDateOfLastSignedPreKeyRenewal(omemoManager);
        }

        //publish
        PubSubManager.getInstance(omemoManager.getConnection(), omemoManager.getOwnJid())
                .tryToPublishAndPossibleAutoCreate(OmemoConstants.PEP_NODE_BUNDLE_FROM_DEVICE_ID(omemoManager.getDeviceId()),
                        new PayloadItem<>(getOmemoStoreBackend().packOmemoBundle(omemoManager)));
    }

    void publishDeviceIdIfNeeded(OmemoManager omemoManager, boolean deleteOtherDevices) throws InterruptedException,
            PubSubException.NotALeafNodeException, XMPPException.XMPPErrorException,
            SmackException.NotConnectedException, SmackException.NoResponseException {
        publishDeviceIdIfNeeded(omemoManager, deleteOtherDevices, false);
    }

    /**
     * Publish our deviceId in case it is not on the list already.
     *
     * @param deleteOtherDevices Do we want to remove other devices from the list?
     *                           If we do, publish the list with only our id, regardless if we were on the list
     *                           already.
     * @throws SmackException.NotConnectedException
     * @throws InterruptedException
     * @throws SmackException.NoResponseException
     * @throws XMPPException.XMPPErrorException
     * @throws PubSubException.NotALeafNodeException
     */
    void publishDeviceIdIfNeeded(OmemoManager omemoManager, boolean deleteOtherDevices, boolean publish)
            throws SmackException.NotConnectedException, InterruptedException, SmackException.NoResponseException,
            XMPPException.XMPPErrorException, PubSubException.NotALeafNodeException {

        CachedDeviceList deviceList = getOmemoStoreBackend().loadCachedDeviceList(omemoManager, omemoManager.getOwnJid());

        Set<Integer> deviceListIds;
        if (deviceList == null) {
            deviceListIds = new HashSet<>();
        } else {
            deviceListIds = new HashSet<>(deviceList.getActiveDevices());
        }

        if (deleteOtherDevices) {
            deviceListIds.clear();
        }

        int ourDeviceId = omemoManager.getDeviceId();
        if (deviceListIds.add(ourDeviceId)) {
            publish = true;
        }

        publish |= removeStaleDevicesIfNeeded(omemoManager, deviceListIds);

        if(publish) {
            publishDeviceIds(omemoManager, new OmemoDeviceListVAxolotlElement(deviceListIds));
        }
    }

    boolean removeStaleDevicesIfNeeded(OmemoManager omemoManager, Set<Integer> deviceListIds) {
        boolean publish = false;
        int ownDeviceId = omemoManager.getDeviceId();
        //Clear devices that we didn't receive a message from for a while
        Iterator<Integer> it = deviceListIds.iterator();
        while(OmemoConfiguration.getInstance().getDeleteStaleDevices() && it.hasNext()) {
            int id = it.next();
            if(id == ownDeviceId) {
                //Skip own id
                continue;
            }

            OmemoDevice d = new OmemoDevice(omemoManager.getOwnJid(), id);
            Date date = getOmemoStoreBackend().getDateOfLastReceivedMessage(omemoManager, d);

            if(date == null) {
                getOmemoStoreBackend().setDateOfLastReceivedMessage(omemoManager, d);
            } else {
                if (System.currentTimeMillis() - date.getTime() > 1000L * 60 * 60 * OmemoConfiguration.getInstance().getDeleteStaleDevicesAfterHours()) {
                    LOGGER.log(Level.INFO, "Remove device " + id + " because of more than " +
                            OmemoConfiguration.getInstance().getDeleteStaleDevicesAfterHours() + " hours of inactivity.");
                    it.remove();
                    publish = true;
                }
            }
        }
        return publish;
    }

    /**
     * Publish the given deviceList to the server.
     *
     * @param deviceList list of deviceIDs
     * @throws InterruptedException                 Exception
     * @throws XMPPException.XMPPErrorException     Exception
     * @throws SmackException.NotConnectedException Exception
     * @throws SmackException.NoResponseException   Exception
     * @throws PubSubException.NotALeafNodeException Exception
     */
    void publishDeviceIds(OmemoManager omemoManager, OmemoDeviceListElement deviceList)
            throws InterruptedException, XMPPException.XMPPErrorException,
            SmackException.NotConnectedException, SmackException.NoResponseException, PubSubException.NotALeafNodeException {
        PubSubManager.getInstance(omemoManager.getConnection(), omemoManager.getOwnJid())
                .tryToPublishAndPossibleAutoCreate(OmemoConstants.PEP_NODE_DEVICE_LIST, new PayloadItem<>(deviceList));
    }

    /**
     * Fetch the deviceList node of a contact.
     *
     * @param contact contact
     * @return LeafNode
     * @throws InterruptedException
     * @throws PubSubException.NotALeafNodeException
     * @throws XMPPException.XMPPErrorException
     * @throws SmackException.NotConnectedException
     * @throws SmackException.NoResponseException
     */
    LeafNode fetchDeviceListNode(OmemoManager omemoManager, BareJid contact)
            throws InterruptedException, PubSubException.NotALeafNodeException, XMPPException.XMPPErrorException,
            SmackException.NotConnectedException, SmackException.NoResponseException {
        try {
            return PubSubManager.getInstance(omemoManager.getConnection(), contact).getLeafNode(PEP_NODE_DEVICE_LIST);
        } catch (PubSubAssertionError.DiscoInfoNodeAssertionError e) {
            //TODO: This is a workaround for ejabberd/#1717
            throw new XMPPException.XMPPErrorException(null,null);
        }
    }

    /**
     * Directly fetch the device list of a contact.
     *
     * @param contact BareJid of the contact
     * @return The OmemoDeviceListElement of the contact
     * @throws XMPPException.XMPPErrorException     When
     * @throws SmackException.NotConnectedException something
     * @throws InterruptedException                 goes
     * @throws SmackException.NoResponseException   wrong
     * @throws PubSubException.NotALeafNodeException when the device lists node is not a LeafNode
     */
    OmemoDeviceListElement fetchDeviceList(OmemoManager omemoManager, BareJid contact) throws XMPPException.XMPPErrorException, SmackException.NotConnectedException, InterruptedException, SmackException.NoResponseException, PubSubException.NotALeafNodeException {
        try {
            return extractDeviceListFrom(fetchDeviceListNode(omemoManager, contact));
        } catch (PubSubAssertionError.DiscoInfoNodeAssertionError e) {
            //TODO: This is a workaround for ejabberd/#1717
            throw new XMPPException.XMPPErrorException(null,null);
        }
    }

    private boolean refreshOwnDeviceList(OmemoManager omemoManager) throws SmackException.NotConnectedException, InterruptedException, SmackException.NoResponseException {
        try {
            getOmemoStoreBackend().mergeCachedDeviceList(omemoManager, omemoManager.getOwnJid(), fetchDeviceList(omemoManager, omemoManager.getOwnJid()));

        } catch (XMPPException.XMPPErrorException e) {

            if(e.getXMPPError().getCondition() == XMPPError.Condition.item_not_found) {
                LOGGER.log(Level.WARNING, "Could not refresh own deviceList, because the node did not exist: "+e.getMessage());
                return true;
            }

        } catch (PubSubException.NotALeafNodeException e) {
            LOGGER.log(Level.WARNING, "Could not refresh own deviceList, because the Node is not a LeafNode: "+e.getMessage());
        }

        catch (PubSubAssertionError.DiscoInfoNodeAssertionError bug) {
            LOGGER.log(Level.WARNING,"This is a bug. will be fixed soon.");
            //TODO: Remove when fixed
            return true;
        }
        return false;
    }

    void refreshDeviceList(OmemoManager omemoManager, BareJid contact) throws SmackException.NotConnectedException, InterruptedException, SmackException.NoResponseException {
        try {
            getOmemoStoreBackend().mergeCachedDeviceList(omemoManager, contact, fetchDeviceList(omemoManager, contact));
        } catch (PubSubException.NotALeafNodeException | XMPPException.XMPPErrorException e) {
            LOGGER.log(Level.WARNING, "Could not fetch device list of "+contact+": "+e.getMessage());
        }

        catch (PubSubAssertionError.DiscoInfoNodeAssertionError bug) {
            LOGGER.log(Level.WARNING, "this is a bug. will be fixed soon");
        }
    }

    /**
     * Fetch the OmemoBundleElement of the contact.
     *
     * @param contact the contacts BareJid
     * @return the OmemoBundleElement of the contact
     * @throws XMPPException.XMPPErrorException     When
     * @throws SmackException.NotConnectedException something
     * @throws InterruptedException                 goes
     * @throws SmackException.NoResponseException   wrong
     * @throws PubSubException.NotALeafNodeException when the bundles node is not a LeafNode
     */
    OmemoBundleVAxolotlElement fetchBundle(OmemoManager omemoManager, OmemoDevice contact) throws XMPPException.XMPPErrorException, SmackException.NotConnectedException, InterruptedException, SmackException.NoResponseException, PubSubException.NotALeafNodeException {
        LeafNode node = PubSubManager.getInstance(omemoManager.getConnection(), contact.getJid()).getLeafNode(PEP_NODE_BUNDLE_FROM_DEVICE_ID(contact.getDeviceId()));
        return extractBundleFrom(node);
    }

    /**
     * Extract the OmemoBundleElement of a contact from a LeafNode.
     *
     * @param node typically a LeafNode containing the OmemoBundles of a contact
     * @return the OmemoBundleElement
     * @throws XMPPException.XMPPErrorException     When
     * @throws SmackException.NotConnectedException something
     * @throws InterruptedException                 goes
     * @throws SmackException.NoResponseException   wrong
     */
    OmemoBundleVAxolotlElement extractBundleFrom(LeafNode node) throws XMPPException.XMPPErrorException, SmackException.NotConnectedException, InterruptedException, SmackException.NoResponseException {
        if (node == null) {
            return null;
        }
        try {
            return (OmemoBundleVAxolotlElement) ((PayloadItem<?>) node.getItems().get(0)).getPayload();
        } catch (IndexOutOfBoundsException e) {
            return null;
        }
    }

    /**
     * Extract the OmemoDeviceListElement of a contact from a node containing his OmemoDeviceListElement.
     *
     * @param node typically a LeafNode containing the OmemoDeviceListElement of a contact
     * @return the extracted OmemoDeviceListElement.
     * @throws XMPPException.XMPPErrorException     When
     * @throws SmackException.NotConnectedException something
     * @throws InterruptedException                 goes
     * @throws SmackException.NoResponseException   wrong
     */
    OmemoDeviceListElement extractDeviceListFrom(LeafNode node) throws XMPPException.XMPPErrorException, SmackException.NotConnectedException, InterruptedException, SmackException.NoResponseException {
        if (node == null) {
            LOGGER.log(Level.WARNING, "DeviceListNode is null.");
            return null;
        }
        List<?> items = node.getItems();
        if(items.size() > 0) {
            OmemoDeviceListVAxolotlElement listElement = (OmemoDeviceListVAxolotlElement) ((PayloadItem<?>) items.get(items.size() - 1)).getPayload();
            if(items.size() > 1) {
                node.deleteAllItems();
                node.send(new PayloadItem<>(listElement));
            }
            return listElement;
        }

        Set<Integer> emptySet = Collections.emptySet();
        return new OmemoDeviceListVAxolotlElement(emptySet);
    }

    /**
     * Subscribe to the device lists of our contacts using PEP.
     */
    private void subscribeToDeviceLists(OmemoManager omemoManager) {
        registerDeviceListListener(omemoManager);
        ServiceDiscoveryManager.getInstanceFor(omemoManager.getConnection()).addFeature(PEP_NODE_DEVICE_LIST_NOTIFY);
    }

    /**
     * Build sessions for all devices of the contact that we do not have a session with yet.
     *
     * @param jid the BareJid of the contact
     */
    private void buildSessionsFromOmemoBundles(OmemoManager omemoManager, BareJid jid) {
        CachedDeviceList devices = getOmemoStoreBackend().loadCachedDeviceList(omemoManager, jid);
        if (devices == null || devices.getAllDevices().isEmpty()) {
            try {
                getOmemoStoreBackend().mergeCachedDeviceList(omemoManager, jid, fetchDeviceList(omemoManager, jid));
            } catch (XMPPException.XMPPErrorException | SmackException.NotConnectedException | InterruptedException | SmackException.NoResponseException | PubSubException.NotALeafNodeException e) {
                LOGGER.log(Level.WARNING, e.getMessage());
            }
        }

        devices = getOmemoStoreBackend().loadCachedDeviceList(omemoManager, jid);
        if (devices == null) {
            return;
        }

        for (int id : devices.getActiveDevices()) {

            OmemoDevice device = new OmemoDevice(jid, id);
            if (getOmemoStoreBackend().getOmemoSessionOf(omemoManager, device) != null) {
                continue;
            }

            //Build missing session
            try {
                buildSessionFromOmemoBundle(omemoManager, device);
            } catch (CannotEstablishOmemoSessionException | CorruptedOmemoKeyException e) {
                LOGGER.log(Level.WARNING, e.getMessage());
                //Skip
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
    public void buildSessionFromOmemoBundle(OmemoManager ommemoManager, OmemoDevice device) throws CannotEstablishOmemoSessionException, CorruptedOmemoKeyException {
        if (device.equals(new OmemoDevice(ommemoManager.getOwnJid(), ommemoManager.getDeviceId()))) {
            LOGGER.log(Level.WARNING, "Do not build a session with yourself!");
            return;
        }

        OmemoBundleVAxolotlElement bundle;
        try {
            bundle = fetchBundle(ommemoManager, device);

        } catch (SmackException | XMPPException.XMPPErrorException | InterruptedException | PubSubAssertionError e) {
            LOGGER.log(Level.WARNING, e.getMessage());
            throw new CannotEstablishOmemoSessionException("Can't build Session for " + device);
        }

        HashMap<Integer, T_Bundle> bundles;
        bundles = getOmemoStoreBackend().keyUtil().BUNDLE.bundles(bundle, device);
        int randomIndex = new Random().nextInt(bundles.size());
        T_Bundle randomPreKeyBundle = new ArrayList<>(bundles.values()).get(randomIndex);
        processBundle(ommemoManager, randomPreKeyBundle, device);
    }

    /**
     * Process a received bundle. Typically that includes saving keys and building a session.
     *
     * @param bundle T_Bundle (depends on used Signal/Olm library)
     * @param device OmemoDevice
     * @throws CorruptedOmemoKeyException
     */
    protected abstract void processBundle(OmemoManager omemoManager, T_Bundle bundle, OmemoDevice device) throws CorruptedOmemoKeyException;

    /**
     * Register a PEPListener that listens for deviceList updates.
     */
    private void registerDeviceListListener(final OmemoManager omemoManager) {
        PEPManager.getInstanceFor(omemoManager.getConnection()).addPEPListener(new PEPListener() {
            @Override
            public void eventReceived(EntityBareJid from, EventElement event, Message message) {
                for (ExtensionElement items : event.getExtensions()) {
                    if (!(items instanceof ItemsExtension)) {
                        continue;
                    }

                    for (ExtensionElement item : ((ItemsExtension) items).getItems()) {
                        if(!(item instanceof  PayloadItem<?>)) {
                            continue;
                        }

                        PayloadItem<?> payloadItem = (PayloadItem<?>) item;

                        if(!(payloadItem.getPayload() instanceof  OmemoDeviceListVAxolotlElement)) {
                            continue;
                        }

                        //Device List <list>
                        OmemoDeviceListVAxolotlElement omemoDeviceListElement = (OmemoDeviceListVAxolotlElement) payloadItem.getPayload();
                        int ourDeviceId = omemoManager.getDeviceId();
                        getOmemoStoreBackend().mergeCachedDeviceList(omemoManager, from, omemoDeviceListElement);

                        if(from == null) {
                            //Unknown sender, no more work to do.
                            //TODO: This DOES happen for some reason. Figure out when...
                            continue;
                        }

                        if (!from.equals(omemoManager.getOwnJid())) {
                            //Not our deviceList, so nothing more to do
                            continue;
                        }

                        if(omemoDeviceListElement.getDeviceIds().contains(ourDeviceId)) {
                            //We are on the list. Nothing more to do
                            continue;
                        }

                        //Our deviceList and we are not on it! We don't want to miss all the action!!!
                        LOGGER.log(Level.INFO, "Our deviceId was not on the list!");
                        Set<Integer> deviceListIds = omemoDeviceListElement.copyDeviceIds();
                        //enroll at the deviceList
                        deviceListIds.add(ourDeviceId);
                        omemoDeviceListElement = new OmemoDeviceListVAxolotlElement(deviceListIds);

                        try {
                            publishDeviceIds(omemoManager, omemoDeviceListElement);
                        } catch (SmackException | InterruptedException | XMPPException.XMPPErrorException e) {
                            //TODO: It might be dangerous NOT to retry publishing our deviceId
                            LOGGER.log(Level.SEVERE,
                                    "Could not publish our device list after an update without our id was received: "
                                            +e.getMessage());
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
     * @param sender        the BareJid of the sender of the message
     * @param message       the encrypted message
     * @param information   OmemoMessageInformation object which will contain meta data about the decrypted message
     * @return decrypted message or null
     * @throws NoRawSessionException
     * @throws InterruptedException
     * @throws SmackException.NoResponseException
     * @throws SmackException.NotConnectedException
     * @throws CryptoFailedException
     * @throws XMPPException.XMPPErrorException
     * @throws CorruptedOmemoKeyException
     */
    private Message processReceivingMessage(OmemoManager omemoManager, OmemoDevice sender, OmemoElement message, final OmemoMessageInformation information)
            throws NoRawSessionException, InterruptedException, SmackException.NoResponseException, SmackException.NotConnectedException,
            CryptoFailedException, XMPPException.XMPPErrorException, CorruptedOmemoKeyException {

        ArrayList<OmemoVAxolotlElement.OmemoHeader.Key> messageRecipientKeys = message.getHeader().getKeys();
        //Do we have a key with our ID in the message?
        for (OmemoVAxolotlElement.OmemoHeader.Key k : messageRecipientKeys) {
            //Only decrypt with our deviceID
            if (k.getId() != omemoManager.getDeviceId()) {
                continue;
            }

            Message decrypted = decryptOmemoMessageElement(omemoManager, sender, message, information);
            if (sender.equals(omemoManager.getOwnJid()) && decrypted != null) {
                getOmemoStoreBackend().setDateOfLastReceivedMessage(omemoManager, sender);
            }
            return decrypted;
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
     * @throws CorruptedOmemoKeyException           When the used OMEMO keys are invalid.
     * @throws NoRawSessionException                When there is no session to decrypt the message with in the double
     *                                              ratchet library
     */
    ClearTextMessage processLocalMessage(OmemoManager omemoManager, BareJid sender, Message message) throws InterruptedException, SmackException.NoResponseException, SmackException.NotConnectedException, CryptoFailedException, XMPPException.XMPPErrorException, CorruptedOmemoKeyException, NoRawSessionException {
        if(OmemoManager.stanzaContainsOmemoElement(message)) {
            OmemoElement omemoMessageElement = message.getExtension(OmemoElement.ENCRYPTED, OMEMO_NAMESPACE_V_AXOLOTL);
            OmemoMessageInformation info = new OmemoMessageInformation();
            Message decrypted = processReceivingMessage(omemoManager,
                    new OmemoDevice(sender, omemoMessageElement.getHeader().getSid()),
                    omemoMessageElement, info);
            return new ClearTextMessage(decrypted != null ? decrypted.getBody() : null, message, info);
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
     * @throws CryptoFailedException
     * @throws UndecidedOmemoIdentityException
     * @throws NoSuchAlgorithmException
     */
    OmemoVAxolotlElement processSendingMessage(OmemoManager manager, BareJid recipient, Message message)
            throws CryptoFailedException, UndecidedOmemoIdentityException, NoSuchAlgorithmException {
        ArrayList<BareJid> recipients = new ArrayList<>();
        recipients.add(recipient);
        return processSendingMessage(manager, recipients, message);
    }

    /**
     * Encrypt a clear text message for the given recipients.
     * The body of the message will be encrypted.
     *
     * @param recipients List of BareJids of all recipients
     * @param message    message to encrypt.
     * @return OmemoMessageElement
     * @throws CryptoFailedException
     * @throws UndecidedOmemoIdentityException
     * @throws NoSuchAlgorithmException
     */
    OmemoVAxolotlElement processSendingMessage(OmemoManager omemoManager, List<BareJid> recipients, Message message)
            throws CryptoFailedException, UndecidedOmemoIdentityException, NoSuchAlgorithmException {
        //Them - The contact wants to read the message on all their devices.
        //Fetch a fresh list in case we had none before.
        List<OmemoDevice> receivers = new ArrayList<>();
        for (BareJid recipient : recipients) {
            if (recipient.equals(omemoManager.getOwnJid())) {
                //Skip our jid
                continue;
            }
            buildSessionsFromOmemoBundles(omemoManager, recipient);
            CachedDeviceList theirDevices = getOmemoStoreBackend().loadCachedDeviceList(omemoManager, recipient);
            for (int id : theirDevices.getActiveDevices()) {
                receivers.add(new OmemoDevice(recipient, id));
            }
        }

        //TODO: What if the recipients list does not exist/not contain any of their keys (they do not support OMEMO)?

        //Us - We want to read the message on all of our devices
        CachedDeviceList ourDevices = getOmemoStoreBackend().loadCachedDeviceList(omemoManager, omemoManager.getOwnJid());
        if (ourDevices == null) {
            ourDevices = new CachedDeviceList();
        }

        for (int id : ourDevices.getActiveDevices()) {

            OmemoDevice d = new OmemoDevice(omemoManager.getOwnJid(), id);
            if(id == omemoManager.getDeviceId()) {
                continue;
            }

            Date lastReceived = getOmemoStoreBackend().getDateOfLastReceivedMessage(omemoManager, d);
            if(lastReceived == null) {
                getOmemoStoreBackend().setDateOfLastReceivedMessage(omemoManager, d);
                lastReceived = new Date();
            }

            if (OmemoConfiguration.getInstance().getIgnoreStaleDevices() && System.currentTimeMillis() - lastReceived.getTime()
                    > 1000L * 60 * 60 * OmemoConfiguration.getInstance().getIgnoreStaleDevicesAfterHours()) {
                LOGGER.log(Level.WARNING, "Refusing to encrypt message for stale device " + d +
                        " which was inactive for at least " + OmemoConfiguration.getInstance().getIgnoreStaleDevicesAfterHours() +" hours.");
            } else {
                receivers.add(new OmemoDevice(omemoManager.getOwnJid(), id));
            }
        }

        return encryptOmemoMessage(omemoManager, receivers, message);
    }

    /**
     * Decrypt a incoming OmemoMessageElement that was sent by the OmemoDevice 'from'.
     *
     * @param from          OmemoDevice that sent the message
     * @param message       Encrypted OmemoMessageElement
     * @param information   OmemoMessageInformation object which will contain metadata about the encryption
     * @return Decrypted message
     * @throws CryptoFailedException when decrypting message fails for some reason
     * @throws InterruptedException
     * @throws CorruptedOmemoKeyException
     * @throws XMPPException.XMPPErrorException
     * @throws SmackException.NotConnectedException
     * @throws SmackException.NoResponseException
     * @throws NoRawSessionException
     */
    private Message decryptOmemoMessageElement(OmemoManager omemoManager, OmemoDevice from, OmemoElement message,
                                               final OmemoMessageInformation information)
            throws CryptoFailedException, InterruptedException, CorruptedOmemoKeyException, XMPPException.XMPPErrorException,
            SmackException.NotConnectedException, SmackException.NoResponseException, NoRawSessionException {

        CipherAndAuthTag transportedKey = decryptTransportedOmemoKey(omemoManager, from, message, information);
        return OmemoSession.decryptMessageElement(message, transportedKey);
    }

    private CipherAndAuthTag decryptTransportedOmemoKey(OmemoManager omemoManager, OmemoDevice  sender,
                                                        OmemoElement omemoMessage,
                                                        OmemoMessageInformation messageInfo)
            throws CryptoFailedException, NoRawSessionException, InterruptedException, CorruptedOmemoKeyException,
            XMPPException.XMPPErrorException, SmackException.NotConnectedException, SmackException.NoResponseException {

        int preKeyCountBefore = getOmemoStoreBackend().loadOmemoPreKeys(omemoManager).size();

        OmemoSession<T_IdKeyPair, T_IdKey, T_PreKey, T_SigPreKey, T_Sess, T_Addr, T_ECPub, T_Bundle, T_Ciph>
                session = getOmemoStoreBackend().getOmemoSessionOf(omemoManager, sender);
        CipherAndAuthTag cipherAndAuthTag = session.decryptTransportedKey(omemoMessage, omemoManager.getDeviceId());

        messageInfo.setSenderDevice(sender);
        messageInfo.setSenderIdentityKey(new IdentityKeyWrapper(session.getIdentityKey()));

        if(preKeyCountBefore != getOmemoStoreBackend().loadOmemoPreKeys(omemoManager).size()) {
            LOGGER.log(Level.INFO, "We used up a preKey. Publish new Bundle.");
            publishBundle(omemoManager);
        }
        return cipherAndAuthTag;
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
    private OmemoVAxolotlElement encryptOmemoMessage(OmemoManager omemoManager, List<OmemoDevice> recipients, Message message)
            throws CryptoFailedException, UndecidedOmemoIdentityException {

        OmemoMessageBuilder<T_IdKeyPair, T_IdKey, T_PreKey, T_SigPreKey, T_Sess, T_Addr, T_ECPub, T_Bundle, T_Ciph>
                builder;
        try {
            builder = new OmemoMessageBuilder<>(omemoManager, getOmemoStoreBackend(), message.getBody());
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
                LOGGER.log(Level.SEVERE, "encryptOmemoMessage failed to establish a session with device "
                        +c+": "+e.getMessage());
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
     * Prepares a keyTransportElement with a random aes key and iv.
     *
     * @param recipients recipients
     * @return KeyTransportElement
     * @throws CryptoFailedException
     * @throws UndecidedOmemoIdentityException
     * @throws CorruptedOmemoKeyException
     * @throws CannotEstablishOmemoSessionException
     */
    OmemoVAxolotlElement prepareOmemoKeyTransportElement(OmemoManager omemoManager, OmemoDevice... recipients) throws CryptoFailedException,
            UndecidedOmemoIdentityException, CorruptedOmemoKeyException, CannotEstablishOmemoSessionException {

        OmemoMessageBuilder<T_IdKeyPair, T_IdKey, T_PreKey, T_SigPreKey, T_Sess, T_Addr, T_ECPub, T_Bundle, T_Ciph>
                builder;
        try {
            builder = new OmemoMessageBuilder<>(omemoManager, getOmemoStoreBackend(), null);

        } catch (UnsupportedEncodingException | BadPaddingException | IllegalBlockSizeException | NoSuchProviderException |
                NoSuchPaddingException | InvalidAlgorithmParameterException | InvalidKeyException | NoSuchAlgorithmException e) {
            throw new CryptoFailedException(e);
        }

        for(OmemoDevice r : recipients) {
            builder.addRecipient(r);
        }

        return builder.finish();
    }

    /**
     * Prepare a KeyTransportElement with aesKey and iv.
     *
     * @param aesKey        AES key
     * @param iv            initialization vector
     * @param recipients    recipients
     * @return              KeyTransportElement
     * @throws CryptoFailedException
     * @throws UndecidedOmemoIdentityException
     * @throws CorruptedOmemoKeyException
     * @throws CannotEstablishOmemoSessionException
     */
    OmemoVAxolotlElement prepareOmemoKeyTransportElement(OmemoManager omemoManager, byte[] aesKey, byte[] iv, OmemoDevice... recipients) throws CryptoFailedException,
            UndecidedOmemoIdentityException, CorruptedOmemoKeyException, CannotEstablishOmemoSessionException {

        OmemoMessageBuilder<T_IdKeyPair, T_IdKey, T_PreKey, T_SigPreKey, T_Sess, T_Addr, T_ECPub, T_Bundle, T_Ciph>
                builder;
        try {
            builder = new OmemoMessageBuilder<>(omemoManager, getOmemoStoreBackend(), aesKey, iv);

        } catch (UnsupportedEncodingException | BadPaddingException | IllegalBlockSizeException | NoSuchProviderException |
                NoSuchPaddingException | InvalidAlgorithmParameterException | InvalidKeyException | NoSuchAlgorithmException e) {
            throw new CryptoFailedException(e);
        }

        for(OmemoDevice r : recipients) {
            builder.addRecipient(r);
        }

        return builder.finish();
    }

    /**
     * Return a new RatchetUpdateMessage.
     * @param recipient     recipient
     * @param preKeyMessage if true, a new session will be built for this message (useful to repair broken sessions)
     *                      otherwise the message will be encrypted using the existing session.
     * @return              OmemoRatchetUpdateMessage
     * @throws CannotEstablishOmemoSessionException
     * @throws CorruptedOmemoKeyException
     * @throws CryptoFailedException
     * @throws UndecidedOmemoIdentityException
     */
    protected Message getOmemoRatchetUpdateMessage(OmemoManager omemoManager, OmemoDevice recipient, boolean preKeyMessage) throws CannotEstablishOmemoSessionException, CorruptedOmemoKeyException, CryptoFailedException, UndecidedOmemoIdentityException {
        if(preKeyMessage) {
            buildSessionFromOmemoBundle(omemoManager, recipient);
        }

        OmemoVAxolotlElement keyTransportElement = prepareOmemoKeyTransportElement(omemoManager, recipient);
        Message ratchetUpdateMessage = omemoManager.finishMessage(keyTransportElement);
        ratchetUpdateMessage.setTo(recipient.getJid());

        return ratchetUpdateMessage;
    }

    /**
     * Send an OmemoRatchetUpdateMessage to recipient. If preKeyMessage is true, the message will be encrypted using a
     * freshly built session. This can be used to repair broken sessions.
     * @param recipient         recipient
     * @param preKeyMessage     shall this be a preKeyMessage?
     * @throws UndecidedOmemoIdentityException
     * @throws CorruptedOmemoKeyException
     * @throws CryptoFailedException
     * @throws CannotEstablishOmemoSessionException
     */
    protected void sendOmemoRatchetUpdateMessage(OmemoManager omemoManager, OmemoDevice recipient, boolean preKeyMessage) throws UndecidedOmemoIdentityException, CorruptedOmemoKeyException, CryptoFailedException, CannotEstablishOmemoSessionException {
        Message ratchetUpdateMessage = getOmemoRatchetUpdateMessage(omemoManager, recipient, preKeyMessage);

        try {
            omemoManager.getConnection().sendStanza(ratchetUpdateMessage);

        } catch (SmackException.NotConnectedException | InterruptedException e) {
            LOGGER.log(Level.WARNING, "sendOmemoRatchetUpdateMessage failed: "+e.getMessage());
        }
    }

    /**
     * Listen for incoming messages and carbons, decrypt them and pass the cleartext messages to the registered
     * OmemoMessageListeners.
     */
    private void registerOmemoMessageStanzaListeners(OmemoManager omemoManager) {
        omemoManager.getConnection().addAsyncStanzaListener(new OmemoStanzaListener(omemoManager, this), omemoStanzaFilter);
        //Carbons
        CarbonManager.getInstanceFor(omemoManager.getConnection())
                .addCarbonCopyReceivedListener(new OmemoCarbonCopyListener(omemoManager, this, omemoStanzaFilter));
    }

    /**
     * StanzaFilter that filters messages containing a OMEMO message element.
     */
    private final StanzaFilter omemoStanzaFilter = new StanzaFilter() {
        @Override
        public boolean accept(Stanza stanza) {
            return stanza instanceof Message && OmemoManager.stanzaContainsOmemoElement(stanza);
        }
    };

    /**
     * Try to decrypt a mamQueryResult. Note that OMEMO messages can only be decrypted once on a device, so if you
     * try to decrypt a message that has been decrypted earlier in time, the decryption will fail. You should handle
     * message history locally when using OMEMO, since you cannot rely on MAM.
     *
     * @param mamQueryResult mamQueryResult that shall be decrypted.
     * @return list of decrypted messages.
     * @throws InterruptedException
     * @throws XMPPException.XMPPErrorException
     * @throws SmackException.NotConnectedException
     * @throws SmackException.NoResponseException
     */
    List<ClearTextMessage> decryptMamQueryResult(OmemoManager omemoManager, MamManager.MamQueryResult mamQueryResult)
            throws InterruptedException, XMPPException.XMPPErrorException, SmackException.NotConnectedException, SmackException.NoResponseException {
        List<ClearTextMessage> result = new ArrayList<>();
        for(Forwarded f : mamQueryResult.forwardedMessages) {
            if(OmemoManager.stanzaContainsOmemoElement(f.getForwardedStanza())) {
                //Decrypt OMEMO messages
                try {
                    result.add(processLocalMessage(omemoManager, f.getForwardedStanza().getFrom().asBareJid(), (Message) f.getForwardedStanza()));
                } catch (NoRawSessionException | CorruptedOmemoKeyException | CryptoFailedException e) {
                    LOGGER.log(Level.WARNING, "decryptMamQueryResult failed to decrypt message from "
                            +f.getForwardedStanza().getFrom()+" due to corrupted session/key: "+e.getMessage());
                }
            } else {
                //Wrap cleartext messages
                Message m = (Message) f.getForwardedStanza();
                result.add(new ClearTextMessage(m.getBody(), m,
                        new OmemoMessageInformation(null, null, OmemoMessageInformation.CARBON.NONE, false)));
            }
        }
        return result;
    }

    /**
     * Return the barejid of the user that sent the message inside the MUC. If the message wasn't sent in a MUC,
     * return null;
     * @param stanza message
     * @return BareJid of the sender.
     */
    private OmemoDevice getSender(OmemoManager omemoManager, Stanza stanza) {
        OmemoElement omemoElement = stanza.getExtension(OmemoElement.ENCRYPTED, OMEMO_NAMESPACE_V_AXOLOTL);
        BareJid sender = stanza.getFrom().asBareJid();
        if(isMucMessage(omemoManager, stanza)) {
            MultiUserChatManager mucm = MultiUserChatManager.getInstanceFor(omemoManager.getConnection());
            MultiUserChat muc = mucm.getMultiUserChat(sender.asEntityBareJidIfPossible());
            sender = muc.getOccupant(sender.asEntityFullJidIfPossible()).getJid().asBareJid();
        }
        if(sender == null) {
            throw new AssertionError("Sender is null.");
        }
        return new OmemoDevice(sender, omemoElement.getHeader().getSid());
    }

    private boolean isMucMessage(OmemoManager omemoManager, Stanza stanza) {
        BareJid sender = stanza.getFrom().asBareJid();
        MultiUserChatManager mucm = MultiUserChatManager.getInstanceFor(omemoManager.getConnection());

        return mucm.getJoinedRooms().contains(sender.asEntityBareJidIfPossible());
    }

    private class OmemoStanzaListener implements StanzaListener {
        private OmemoManager omemoManager;
        private OmemoService<T_IdKeyPair, T_IdKey, T_PreKey, T_SigPreKey, T_Sess, T_Addr, T_ECPub, T_Bundle, T_Ciph> service;

        OmemoStanzaListener(OmemoManager omemoManager,
                            OmemoService<T_IdKeyPair, T_IdKey, T_PreKey, T_SigPreKey, T_Sess, T_Addr, T_ECPub, T_Bundle, T_Ciph> service) {
            this.omemoManager = omemoManager;
            this.service = service;
        }

        @Override
        public void processStanza(Stanza stanza) throws SmackException.NotConnectedException, InterruptedException {
            Message decrypted;
            OmemoElement omemoMessage = stanza.getExtension(OmemoElement.ENCRYPTED, OMEMO_NAMESPACE_V_AXOLOTL);
            OmemoMessageInformation messageInfo = new OmemoMessageInformation();
            MultiUserChatManager mucm = MultiUserChatManager.getInstanceFor(omemoManager.getConnection());
            OmemoDevice senderDevice = getSender(omemoManager, stanza);
            try {
                //Is it a MUC message...
                if (isMucMessage(omemoManager, stanza)) {

                    MultiUserChat muc = mucm.getMultiUserChat(stanza.getFrom().asEntityBareJidIfPossible());
                    if (omemoMessage.isMessageElement()) {

                        decrypted = processReceivingMessage(omemoManager, senderDevice, omemoMessage, messageInfo);
                        if (decrypted != null) {
                            omemoManager.notifyOmemoMucMessageReceived(muc, senderDevice.getJid(), decrypted.getBody(),
                                    (Message) stanza, null, messageInfo);
                        }

                    } else if (omemoMessage.isKeyTransportElement()) {

                        CipherAndAuthTag cipherAndAuthTag = decryptTransportedOmemoKey(omemoManager, senderDevice, omemoMessage, messageInfo);
                        if(cipherAndAuthTag != null) {
                            omemoManager.notifyOmemoMucKeyTransportMessageReceived(muc, senderDevice.getJid(), cipherAndAuthTag,
                                    (Message) stanza, null, messageInfo);
                        }
                    }
                }
                //... or a normal chat message...
                else {
                    if (omemoMessage.isMessageElement()) {

                        decrypted = service.processReceivingMessage(omemoManager, senderDevice, omemoMessage, messageInfo);
                        if (decrypted != null) {
                            omemoManager.notifyOmemoMessageReceived(decrypted.getBody(), (Message) stanza, null, messageInfo);
                        }

                    } else if (omemoMessage.isKeyTransportElement()) {

                        CipherAndAuthTag cipherAndAuthTag = decryptTransportedOmemoKey(omemoManager, senderDevice, omemoMessage, messageInfo);
                        if(cipherAndAuthTag != null) {
                            omemoManager.notifyOmemoKeyTransportMessageReceived(cipherAndAuthTag, (Message) stanza, null, messageInfo);
                        }
                    }
                }

            } catch (CryptoFailedException | CorruptedOmemoKeyException | InterruptedException | SmackException.NotConnectedException | XMPPException.XMPPErrorException | SmackException.NoResponseException e) {
                LOGGER.log(Level.WARNING, "internal omemoMessageListener failed to decrypt incoming OMEMO message: "
                        +e.getMessage());

            } catch (NoRawSessionException e) {
                try {
                    LOGGER.log(Level.INFO, "Received message with invalid session from " +
                            senderDevice + ". Send RatchetUpdateMessage.");
                    service.sendOmemoRatchetUpdateMessage(omemoManager, senderDevice, true);

                } catch (UndecidedOmemoIdentityException | CorruptedOmemoKeyException | CannotEstablishOmemoSessionException | CryptoFailedException e1) {
                    LOGGER.log(Level.WARNING, "internal omemoMessageListener failed to establish a session for incoming OMEMO message: "
                            +e.getMessage());
                }
            }
        }
    }

    private class OmemoCarbonCopyListener implements CarbonCopyReceivedListener {

        private final OmemoManager omemoManager;
        private final OmemoService<T_IdKeyPair, T_IdKey, T_PreKey, T_SigPreKey, T_Sess, T_Addr, T_ECPub, T_Bundle, T_Ciph> service;
        private final StanzaFilter filter;

        public OmemoCarbonCopyListener(OmemoManager omemoManager,
                                       OmemoService<T_IdKeyPair, T_IdKey, T_PreKey, T_SigPreKey, T_Sess, T_Addr, T_ECPub, T_Bundle, T_Ciph> service,
                                       StanzaFilter filter) {
            this.omemoManager = omemoManager;
            this.service = service;
            this.filter = filter;
        }

        @Override
        public void onCarbonCopyReceived(CarbonExtension.Direction direction, Message carbonCopy, Message wrappingMessage) {
            if (filter.accept(carbonCopy)) {
                OmemoDevice senderDevice = getSender(omemoManager, carbonCopy);
                Message decrypted;
                MultiUserChatManager mucm = MultiUserChatManager.getInstanceFor(omemoManager.getConnection());
                OmemoElement omemoMessage = carbonCopy.getExtension(OmemoElement.ENCRYPTED, OMEMO_NAMESPACE_V_AXOLOTL);
                OmemoMessageInformation messageInfo = new OmemoMessageInformation();

                if (CarbonExtension.Direction.received.equals(direction)) {
                    messageInfo.setCarbon(OmemoMessageInformation.CARBON.RECV);
                } else {
                    messageInfo.setCarbon(OmemoMessageInformation.CARBON.SENT);
                }

                try {
                    //Is it a MUC message...
                    if (isMucMessage(omemoManager, carbonCopy)) {

                        MultiUserChat muc = mucm.getMultiUserChat(carbonCopy.getFrom().asEntityBareJidIfPossible());
                        if (omemoMessage.isMessageElement()) {

                            decrypted = processReceivingMessage(omemoManager, senderDevice, omemoMessage, messageInfo);
                            if (decrypted != null) {
                                omemoManager.notifyOmemoMucMessageReceived(muc, senderDevice.getJid(), decrypted.getBody(),
                                        carbonCopy, wrappingMessage, messageInfo);
                            }

                        } else if (omemoMessage.isKeyTransportElement()) {

                            CipherAndAuthTag cipherAndAuthTag = decryptTransportedOmemoKey(omemoManager, senderDevice, omemoMessage, messageInfo);
                            if(cipherAndAuthTag != null) {
                                omemoManager.notifyOmemoMucKeyTransportMessageReceived(muc, senderDevice.getJid(), cipherAndAuthTag,
                                        carbonCopy, wrappingMessage, messageInfo);
                            }
                        }
                    }
                    //... or a normal chat message...
                    else {
                        if (omemoMessage.isMessageElement()) {

                            decrypted = service.processReceivingMessage(omemoManager, senderDevice, omemoMessage, messageInfo);
                            if (decrypted != null) {
                                omemoManager.notifyOmemoMessageReceived(decrypted.getBody(), carbonCopy, null, messageInfo);
                            }

                        } else if (omemoMessage.isKeyTransportElement()) {

                            CipherAndAuthTag cipherAndAuthTag = decryptTransportedOmemoKey(omemoManager, senderDevice, omemoMessage, messageInfo);
                            if(cipherAndAuthTag != null) {
                                omemoManager.notifyOmemoKeyTransportMessageReceived(cipherAndAuthTag, carbonCopy, null, messageInfo);
                            }
                        }
                    }

                } catch (CryptoFailedException | CorruptedOmemoKeyException | InterruptedException | SmackException.NotConnectedException | XMPPException.XMPPErrorException | SmackException.NoResponseException e) {
                    LOGGER.log(Level.WARNING, "internal omemoMessageListener failed to decrypt incoming OMEMO carbon copy: "
                            +e.getMessage());

                } catch (NoRawSessionException e) {
                    try {
                        LOGGER.log(Level.INFO, "Received OMEMO carbon copy message with invalid session from " +
                                senderDevice + ". Send RatchetUpdateMessage.");
                        service.sendOmemoRatchetUpdateMessage(omemoManager, senderDevice, true);

                    } catch (UndecidedOmemoIdentityException | CorruptedOmemoKeyException | CannotEstablishOmemoSessionException | CryptoFailedException e1) {
                        LOGGER.log(Level.WARNING, "internal omemoMessageListener failed to establish a session for incoming OMEMO carbon message: "
                                +e.getMessage());
                    }
                }
            }
        }
    }
}
