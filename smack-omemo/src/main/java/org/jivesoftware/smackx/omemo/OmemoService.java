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

    protected static final Logger LOGGER = Logger.getLogger(OmemoService.class.getName());
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

    protected HashMap<OmemoManager, OmemoStore<T_IdKeyPair, T_IdKey, T_PreKey, T_SigPreKey, T_Sess, T_Addr, T_ECPub, T_Bundle, T_Ciph>>
    omemoStores = new HashMap<>();

    /**
     * Initialize OMEMO functionality. Should be called once after the service has been created.
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

        if (getOmemoStore(omemoManager).isFreshInstallation()) {
            LOGGER.log(Level.INFO, "No key material found. Looks like we have a fresh installation.");
            //Create new key material and publish it to the server
            regenerate(omemoManager, omemoManager.getDeviceId());
        }

        //Get fresh device list from server
        boolean mustPublishId = refreshOwnDeviceList(omemoManager);

        publishDeviceIdIfNeeded(omemoManager, false, mustPublishId);
        publishBundle(omemoManager);

        subscribeToDeviceLists(omemoManager);
        registerOmemoMessageStanzaListeners(omemoManager);  //Wait for new OMEMO messages
        getOmemoStore(omemoManager).initializeOmemoSessions();   //Preload existing OMEMO sessions
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
    void regenerate(OmemoManager manager, Integer nDeviceId) throws CorruptedOmemoKeyException {
        //Generate unique ID that is not already taken
        OmemoStore<T_IdKeyPair, T_IdKey, T_PreKey, T_SigPreKey, T_Sess, T_Addr, T_ECPub, T_Bundle, T_Ciph> omemoStore = getOmemoStore(manager);

        while (nDeviceId == null || !omemoStore.isAvailableDeviceId(nDeviceId)) {
            nDeviceId = OmemoManager.randomDeviceId();
        }

        omemoStore.purgeOwnDeviceKeys();
        manager.setDeviceId(nDeviceId);
        omemoStore.regenerate();
    }

    /**
     * Publish a fresh bundle to the server.
     * @throws SmackException.NotConnectedException
     * @throws InterruptedException
     * @throws SmackException.NoResponseException
     * @throws CorruptedOmemoKeyException
     * @throws XMPPException.XMPPErrorException
     */
    void publishBundle(OmemoManager manager)
            throws SmackException.NotConnectedException, InterruptedException,
            SmackException.NoResponseException, CorruptedOmemoKeyException, XMPPException.XMPPErrorException {
        OmemoStore<T_IdKeyPair, T_IdKey, T_PreKey, T_SigPreKey, T_Sess, T_Addr, T_ECPub, T_Bundle, T_Ciph> omemoStore = getOmemoStore(manager);
        Date lastSignedPreKeyRenewal = omemoStore.getDateOfLastSignedPreKeyRenewal();
        if(OmemoManager.getRenewOldSignedPreKeys() && lastSignedPreKeyRenewal != null) {
            if(System.currentTimeMillis() - lastSignedPreKeyRenewal.getTime()
                    > 1000L * 60 * 60 * OmemoManager.getRenewOldSignedPreKeysAfterHours()) {
                LOGGER.log(Level.INFO, "Renewing signedPreKey");
                omemoStore.changeSignedPreKey();
            }
        } else {
            omemoStore.setDateOfLastSignedPreKeyRenewal();
        }

        //publish
        PubSubManager.getInstance(manager.getConnection(), manager.getOwnJid())
                .tryToPublishAndPossibleAutoCreate(OmemoConstants.PEP_NODE_BUNDLE_FROM_DEVICE_ID(manager.getDeviceId()),
                        new PayloadItem<>(omemoStore.packOmemoBundle()));
    }

    void publishDeviceIdIfNeeded(OmemoManager manager, boolean deleteOtherDevices) throws InterruptedException,
            PubSubException.NotALeafNodeException, XMPPException.XMPPErrorException,
            SmackException.NotConnectedException, SmackException.NoResponseException {
        publishDeviceIdIfNeeded(manager, deleteOtherDevices, false);
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
    void publishDeviceIdIfNeeded(OmemoManager manager, boolean deleteOtherDevices, boolean publish)
            throws SmackException.NotConnectedException, InterruptedException, SmackException.NoResponseException,
            XMPPException.XMPPErrorException, PubSubException.NotALeafNodeException {

        CachedDeviceList deviceList = getOmemoStore(manager).loadCachedDeviceList(manager.getOwnJid());

        Set<Integer> deviceListIds;
        if (deviceList == null) {
            deviceListIds = new HashSet<>();
        } else {
            deviceListIds = new HashSet<>(deviceList.getActiveDevices());
        }

        if (deleteOtherDevices) {
            deviceListIds.clear();
        }

        int ourDeviceId = manager.getDeviceId();
        if (deviceListIds.add(ourDeviceId)) {
            publish = true;
        }

        publish |= removeStaleDevicesIfNeeded(manager, deviceListIds);

        if(publish) {
            publishDeviceIds(manager, new OmemoDeviceListVAxolotlElement(deviceListIds));
        }
    }

    boolean removeStaleDevicesIfNeeded(OmemoManager manager, Set<Integer> deviceListIds) {
        OmemoStore<T_IdKeyPair, T_IdKey, T_PreKey, T_SigPreKey, T_Sess, T_Addr, T_ECPub, T_Bundle, T_Ciph> omemoStore = getOmemoStore(manager);
        boolean publish = false;
        int ownDeviceId = manager.getDeviceId();
        //Clear devices that we didn't receive a message from for a while
        Iterator<Integer> it = deviceListIds.iterator();
        while(OmemoManager.getDeleteStaleDevices() && it.hasNext()) {
            int id = it.next();
            if(id == ownDeviceId) {
                //Skip own id
                continue;
            }

            OmemoDevice d = new OmemoDevice(manager.getOwnJid(), id);
            Date date = omemoStore.getDateOfLastReceivedMessage(d);

            if(date == null) {
                omemoStore.setDateOfLastReceivedMessage(d);
            } else {
                if (System.currentTimeMillis() - date.getTime() > 1000L * 60 * 60 * OmemoManager.getDeleteStaleDevicesAfterHours()) {
                    LOGGER.log(Level.INFO, "Remove device " + id + " because of more than " +
                            OmemoManager.getDeleteStaleDevicesAfterHours() + " hours of inactivity.");
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
    void publishDeviceIds(OmemoManager manager, OmemoDeviceListElement deviceList)
            throws InterruptedException, XMPPException.XMPPErrorException,
            SmackException.NotConnectedException, SmackException.NoResponseException, PubSubException.NotALeafNodeException {
        PubSubManager.getInstance(manager.getConnection(), manager.getOwnJid())
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
    LeafNode fetchDeviceListNode(OmemoManager manager, BareJid contact)
            throws InterruptedException, PubSubException.NotALeafNodeException, XMPPException.XMPPErrorException,
            SmackException.NotConnectedException, SmackException.NoResponseException {
        return PubSubManager.getInstance(manager.getConnection(), contact).getLeafNode(PEP_NODE_DEVICE_LIST);
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
    OmemoDeviceListElement fetchDeviceList(OmemoManager manager, BareJid contact) throws XMPPException.XMPPErrorException, SmackException.NotConnectedException, InterruptedException, SmackException.NoResponseException, PubSubException.NotALeafNodeException {
        return extractDeviceListFrom(fetchDeviceListNode(manager, contact));
    }

    private boolean refreshOwnDeviceList(OmemoManager manager) throws SmackException.NotConnectedException, InterruptedException, SmackException.NoResponseException {
        try {
            getOmemoStore(manager).mergeCachedDeviceList(manager.getOwnJid(), fetchDeviceList(manager, manager.getOwnJid()));

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

    void refreshDeviceList(OmemoManager manager, BareJid contact) throws SmackException.NotConnectedException, InterruptedException, SmackException.NoResponseException {
        try {
            getOmemoStore(manager).mergeCachedDeviceList(contact, fetchDeviceList(manager, contact));
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
    OmemoBundleVAxolotlElement fetchBundle(OmemoManager manager, OmemoDevice contact) throws XMPPException.XMPPErrorException, SmackException.NotConnectedException, InterruptedException, SmackException.NoResponseException, PubSubException.NotALeafNodeException {
        LeafNode node = PubSubManager.getInstance(manager.getConnection(), contact.getJid()).getLeafNode(PEP_NODE_BUNDLE_FROM_DEVICE_ID(contact.getDeviceId()));
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
    private void subscribeToDeviceLists(OmemoManager manager) {
        registerDeviceListListener(manager);
        ServiceDiscoveryManager.getInstanceFor(manager.getConnection()).addFeature(PEP_NODE_DEVICE_LIST_NOTIFY);
    }

    /**
     * Build sessions for all devices of the contact that we do not have a session with yet.
     *
     * @param jid the BareJid of the contact
     */
    private void buildSessionsFromOmemoBundles(OmemoManager manager, BareJid jid) {
        OmemoStore<T_IdKeyPair, T_IdKey, T_PreKey, T_SigPreKey, T_Sess, T_Addr, T_ECPub, T_Bundle, T_Ciph> omemoStore = getOmemoStore(manager);
        CachedDeviceList devices = omemoStore.loadCachedDeviceList(jid);
        if (devices == null) {
            try {
                omemoStore.mergeCachedDeviceList(jid, fetchDeviceList(manager, jid));
            } catch (XMPPException.XMPPErrorException | SmackException.NotConnectedException | InterruptedException | SmackException.NoResponseException | PubSubException.NotALeafNodeException e) {
                LOGGER.log(Level.WARNING, e.getMessage());
            }
        }

        devices = omemoStore.loadCachedDeviceList(jid);
        if (devices == null) {
            return;
        }

        for (int id : devices.getActiveDevices()) {

            OmemoDevice device = new OmemoDevice(jid, id);
            if (omemoStore.getOmemoSessionOf(device) != null) {
                continue;
            }

            //Build missing session
            try {
                buildSessionFromOmemoBundle(manager, device);
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
    public void buildSessionFromOmemoBundle(OmemoManager manager, OmemoDevice device) throws CannotEstablishOmemoSessionException, CorruptedOmemoKeyException {
        if (device.equals(new OmemoDevice(manager.getOwnJid(), manager.getDeviceId()))) {
            LOGGER.log(Level.WARNING, "Do not build a session with yourself!");
            return;
        }

        OmemoBundleVAxolotlElement bundle;
        try {
            bundle = fetchBundle(manager, device);

        } catch (SmackException | XMPPException.XMPPErrorException | InterruptedException | PubSubAssertionError e) {
            LOGGER.log(Level.WARNING, e.getMessage());
            throw new CannotEstablishOmemoSessionException("Can't build Session for " + device);
        }

        HashMap<Integer, T_Bundle> bundles;
        bundles = getOmemoStore(manager).keyUtil().BUNDLE.bundles(bundle, device);
        int randomIndex = new Random().nextInt(bundles.size());
        T_Bundle randomPreKeyBundle = new ArrayList<>(bundles.values()).get(randomIndex);
        processBundle(manager, randomPreKeyBundle, device);
    }

    /**
     * Process a received bundle. Typically that includes saving keys and building a session.
     *
     * @param bundle T_Bundle (depends on used Signal/Olm library)
     * @param device OmemoDevice
     * @throws CorruptedOmemoKeyException
     */
    protected abstract void processBundle(OmemoManager manager, T_Bundle bundle, OmemoDevice device) throws CorruptedOmemoKeyException;

    /**
     * Register a PEPListener that listens for deviceList updates.
     */
    private void registerDeviceListListener(final OmemoManager manager) {
        PEPManager.getInstanceFor(manager.getConnection()).addPEPListener(new PEPListener() {
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
                        int ourDeviceId = manager.getDeviceId();
                        getOmemoStore(manager).mergeCachedDeviceList(from, omemoDeviceListElement);

                        if(from == null) {
                            //Unknown sender, no more work to do.
                            //TODO: This DOES happen for some reason. Figure out when...
                            continue;
                        }

                        if (!from.equals(manager.getOwnJid())) {
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
                            publishDeviceIds(manager, omemoDeviceListElement);
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
    private Message processReceivingMessage(OmemoManager manager, BareJid sender, OmemoElement message, final OmemoMessageInformation information)
            throws NoRawSessionException, InterruptedException, SmackException.NoResponseException, SmackException.NotConnectedException,
            CryptoFailedException, XMPPException.XMPPErrorException, CorruptedOmemoKeyException {
        OmemoStore<T_IdKeyPair, T_IdKey, T_PreKey, T_SigPreKey, T_Sess, T_Addr, T_ECPub, T_Bundle, T_Ciph> omemoStore = getOmemoStore(manager);
        ArrayList<OmemoVAxolotlElement.OmemoHeader.Key> messageRecipientKeys = message.getHeader().getKeys();

        //Do we have a key with our ID in the message?
        for (OmemoVAxolotlElement.OmemoHeader.Key k : messageRecipientKeys) {

            if (k.getId() != manager.getDeviceId()) {
                continue;
            }

            OmemoDevice d = new OmemoDevice(sender, message.getHeader().getSid());
            Message decrypted = decryptOmemoMessageElement(manager, d, message, information);
            if(sender.equals(manager.getOwnJid()) && decrypted != null) {
                omemoStore.setDateOfLastReceivedMessage(d);
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
    ClearTextMessage processLocalMessage(OmemoManager manager, BareJid sender, Message message) throws InterruptedException, SmackException.NoResponseException, SmackException.NotConnectedException, CryptoFailedException, XMPPException.XMPPErrorException, CorruptedOmemoKeyException, NoRawSessionException {
        if(OmemoManager.stanzaContainsOmemoElement(message)) {
            OmemoElement omemoMessageElement = message.getExtension(OmemoElement.ENCRYPTED, OMEMO_NAMESPACE_V_AXOLOTL);
            OmemoMessageInformation info = new OmemoMessageInformation();
            Message decrypted = processReceivingMessage(manager, sender, omemoMessageElement, info);
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
    OmemoVAxolotlElement processSendingMessage(OmemoManager manager, List<BareJid> recipients, Message message)
            throws CryptoFailedException, UndecidedOmemoIdentityException, NoSuchAlgorithmException {
        //Them - The contact wants to read the message on all their devices.
        //Fetch a fresh list in case we had none before.
        OmemoStore<T_IdKeyPair, T_IdKey, T_PreKey, T_SigPreKey, T_Sess, T_Addr, T_ECPub, T_Bundle, T_Ciph> omemoStore = getOmemoStore(manager);
        List<OmemoDevice> receivers = new ArrayList<>();
        for (BareJid recipient : recipients) {
            if (recipient.equals(manager.getOwnJid())) {
                //Skip our jid
                continue;
            }
            buildSessionsFromOmemoBundles(manager, recipient);
            CachedDeviceList theirDevices = omemoStore.loadCachedDeviceList(recipient);
            for (int id : theirDevices.getActiveDevices()) {
                receivers.add(new OmemoDevice(recipient, id));
            }
        }

        //TODO: What if the recipients list does not exist/not contain any of their keys (they do not support OMEMO)?

        //Us - We want to read the message on all of our devices
        CachedDeviceList ourDevices = omemoStore.loadCachedDeviceList(manager.getOwnJid());
        if (ourDevices == null) {
            ourDevices = new CachedDeviceList();
        }

        for (int id : ourDevices.getActiveDevices()) {

            OmemoDevice d = new OmemoDevice(manager.getOwnJid(), id);
            if(id == manager.getDeviceId()) {
                continue;
            }

            Date lastReceived = omemoStore.getDateOfLastReceivedMessage(d);
            if(lastReceived == null) {
                omemoStore.setDateOfLastReceivedMessage(d);
                lastReceived = new Date();
            }

            if (OmemoManager.getIgnoreStaleDevices() && System.currentTimeMillis() - lastReceived.getTime()
                    > 1000L * 60 * 60 * OmemoManager.getIgnoreStaleDevicesAfterHours()) {
                LOGGER.log(Level.WARNING, "Refusing to encrypt message for stale device " + d +
                        " which was inactive for at least " + OmemoManager.getIgnoreStaleDevicesAfterHours() +" hours.");
            } else {
                receivers.add(new OmemoDevice(manager.getOwnJid(), id));
            }
        }

        return encryptOmemoMessage(manager, receivers, message);
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
    private Message decryptOmemoMessageElement(OmemoManager manager, OmemoDevice from, OmemoElement message, final OmemoMessageInformation information)
            throws CryptoFailedException, InterruptedException, CorruptedOmemoKeyException, XMPPException.XMPPErrorException,
            SmackException.NotConnectedException, SmackException.NoResponseException, NoRawSessionException {
        OmemoStore<T_IdKeyPair, T_IdKey, T_PreKey, T_SigPreKey, T_Sess, T_Addr, T_ECPub, T_Bundle, T_Ciph> omemoStore = getOmemoStore(manager);
        int preKeyCountBefore = omemoStore.loadOmemoPreKeys().size();
        Message decrypted;

        //Get the session that will decrypt the message. If we have no such session, create a new one.
        OmemoSession<T_IdKeyPair, T_IdKey, T_PreKey, T_SigPreKey, T_Sess, T_Addr, T_ECPub, T_Bundle, T_Ciph> session = omemoStore.getOmemoSessionOf(from);
        if (session != null) {
            decrypted = session.decryptMessageElement(message, manager.getDeviceId());
        } else {
            session = omemoStore.keyUtil().createOmemoSession(omemoStore, from);
            decrypted = session.decryptMessageElement(message, manager.getDeviceId());
        }

        information.setSenderDevice(from);
        information.setSenderIdentityKey(new IdentityKeyWrapper(session.getIdentityKey()));

        // Check, if we use up a preKey (the message was a PreKeyMessage)
        // If we did, republish a bundle with the used keys replaced with fresh keys
        // TODO: Do this AFTER returning the message?
        if (omemoStore.loadOmemoPreKeys().size() != preKeyCountBefore) {
            LOGGER.log(Level.INFO, "We used up a preKey. Publish new Bundle.");
            publishBundle(manager);
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
    private OmemoVAxolotlElement encryptOmemoMessage(OmemoManager manager, List<OmemoDevice> recipients, Message message)
            throws CryptoFailedException, UndecidedOmemoIdentityException {
        OmemoStore<T_IdKeyPair, T_IdKey, T_PreKey, T_SigPreKey, T_Sess, T_Addr, T_ECPub, T_Bundle, T_Ciph> omemoStore = getOmemoStore(manager);
        OmemoMessageBuilder<T_IdKeyPair, T_IdKey, T_PreKey, T_SigPreKey, T_Sess, T_Addr, T_ECPub, T_Bundle, T_Ciph>
                builder;
        try {
            builder = new OmemoMessageBuilder<>(manager, omemoStore, message.getBody());
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
    OmemoVAxolotlElement prepareOmemoKeyTransportElement(OmemoManager manager, OmemoDevice... recipients) throws CryptoFailedException,
            UndecidedOmemoIdentityException, CorruptedOmemoKeyException, CannotEstablishOmemoSessionException {
        OmemoStore<T_IdKeyPair, T_IdKey, T_PreKey, T_SigPreKey, T_Sess, T_Addr, T_ECPub, T_Bundle, T_Ciph> omemoStore = getOmemoStore(manager);
        OmemoMessageBuilder<T_IdKeyPair, T_IdKey, T_PreKey, T_SigPreKey, T_Sess, T_Addr, T_ECPub, T_Bundle, T_Ciph>
                builder;
        try {
            builder = new OmemoMessageBuilder<>(manager, omemoStore, null);

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
    OmemoVAxolotlElement prepareOmemoKeyTransportElement(OmemoManager manager, byte[] aesKey, byte[] iv, OmemoDevice... recipients) throws CryptoFailedException,
            UndecidedOmemoIdentityException, CorruptedOmemoKeyException, CannotEstablishOmemoSessionException {
        OmemoStore<T_IdKeyPair, T_IdKey, T_PreKey, T_SigPreKey, T_Sess, T_Addr, T_ECPub, T_Bundle, T_Ciph> omemoStore = getOmemoStore(manager);
        OmemoMessageBuilder<T_IdKeyPair, T_IdKey, T_PreKey, T_SigPreKey, T_Sess, T_Addr, T_ECPub, T_Bundle, T_Ciph>
                builder;
        try {
            builder = new OmemoMessageBuilder<>(manager, omemoStore, aesKey, iv);

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
    protected Message getOmemoRatchetUpdateMessage(OmemoManager manager, OmemoDevice recipient, boolean preKeyMessage) throws CannotEstablishOmemoSessionException, CorruptedOmemoKeyException, CryptoFailedException, UndecidedOmemoIdentityException {
        if(preKeyMessage) {
            buildSessionFromOmemoBundle(manager, recipient);
        }

        OmemoVAxolotlElement keyTransportElement = prepareOmemoKeyTransportElement(manager, recipient);
        Message ratchetUpdateMessage = manager.finishMessage(keyTransportElement);
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
    protected void sendOmemoRatchetUpdateMessage(OmemoManager manager, OmemoDevice recipient, boolean preKeyMessage) throws UndecidedOmemoIdentityException, CorruptedOmemoKeyException, CryptoFailedException, CannotEstablishOmemoSessionException {
        Message ratchetUpdateMessage = getOmemoRatchetUpdateMessage(manager, recipient, preKeyMessage);

        try {
            manager.getConnection().sendStanza(ratchetUpdateMessage);

        } catch (SmackException.NotConnectedException | InterruptedException e) {
            LOGGER.log(Level.WARNING, "sendOmemoRatchetUpdateMessage failed: "+e.getMessage());
        }
    }

    /**
     * Return our OmemoStore.
     *
     * @return our store
     */
    public OmemoStore<T_IdKeyPair, T_IdKey, T_PreKey, T_SigPreKey, T_Sess, T_Addr, T_ECPub, T_Bundle, T_Ciph>
    getOmemoStore(OmemoManager manager) {
        return omemoStores.get(manager);
    }

    public void setOmemoStore(OmemoManager manager,
                              OmemoStore<T_IdKeyPair, T_IdKey, T_PreKey, T_SigPreKey, T_Sess, T_Addr, T_ECPub, T_Bundle, T_Ciph> store) {
        omemoStores.put(manager, store);
    }

    /**
     * Listen for incoming messages and carbons, decrypt them and pass the cleartext messages to the registered
     * OmemoMessageListeners.
     */
    private void registerOmemoMessageStanzaListeners(OmemoManager manager) {
        manager.getConnection().addAsyncStanzaListener(new OmemoStanzaListener(manager, this), omemoStanzaFilter);
        //Carbons
        CarbonManager.getInstanceFor(manager.getConnection())
                .addCarbonCopyReceivedListener(new OmemoCarbonCopyListener(manager, this, omemoStanzaFilter));
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
    List<ClearTextMessage> decryptMamQueryResult(OmemoManager manager, MamManager.MamQueryResult mamQueryResult)
            throws InterruptedException, XMPPException.XMPPErrorException, SmackException.NotConnectedException, SmackException.NoResponseException {
        List<ClearTextMessage> result = new ArrayList<>();
        for(Forwarded f : mamQueryResult.forwardedMessages) {
            if(OmemoManager.stanzaContainsOmemoElement(f.getForwardedStanza())) {
                //Decrypt OMEMO messages
                try {
                    result.add(processLocalMessage(manager, f.getForwardedStanza().getFrom().asBareJid(), (Message) f.getForwardedStanza()));
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
    private BareJid getSenderBareJidFromMucMessage(OmemoManager manager, Stanza stanza) {
        BareJid sender = stanza.getFrom().asBareJid();
        MultiUserChatManager mucm = MultiUserChatManager.getInstanceFor(manager.getConnection());
        //MultiUserChat
        if(mucm.getJoinedRooms().contains(sender.asEntityBareJidIfPossible())) {
            MultiUserChat muc = mucm.getMultiUserChat(sender.asEntityBareJidIfPossible());
            return muc.getOccupant(sender.asEntityFullJidIfPossible()).getJid().asBareJid();
        }
        return null;
    }

    private class OmemoStanzaListener implements StanzaListener {
        private OmemoManager manager;
        private OmemoService<T_IdKeyPair, T_IdKey, T_PreKey, T_SigPreKey, T_Sess, T_Addr, T_ECPub, T_Bundle, T_Ciph> service;

        public OmemoStanzaListener(OmemoManager manager,
                                   OmemoService<T_IdKeyPair, T_IdKey, T_PreKey, T_SigPreKey, T_Sess, T_Addr, T_ECPub, T_Bundle, T_Ciph> service) {
            this.manager = manager;
            this.service = service;
        }

        @Override
        public void processStanza(Stanza packet) throws SmackException.NotConnectedException, InterruptedException {
            Message decrypted;
            BareJid sender = service.getSenderBareJidFromMucMessage(manager, packet);
            OmemoVAxolotlElement omemoMessage = packet.getExtension(OmemoElement.ENCRYPTED, OMEMO_NAMESPACE_V_AXOLOTL);
            OmemoMessageInformation messageInfo = new OmemoMessageInformation();
            MultiUserChatManager mucm = MultiUserChatManager.getInstanceFor(manager.getConnection());

            try {
                //Is it a MUC message...
                if (sender != null) {
                    MultiUserChat muc = mucm.getMultiUserChat(packet.getFrom().asEntityBareJidIfPossible());
                    decrypted = service.processReceivingMessage(manager, sender, omemoMessage, messageInfo);
                    if (decrypted != null) {
                        manager.notifyOmemoMucMessageReceived(muc, sender, decrypted.getBody(), (Message) packet, null, messageInfo);
                    }
                }
                //... or a normal chat message...
                else {
                    sender = packet.getFrom().asBareJid();
                    decrypted = service.processReceivingMessage(manager, sender, omemoMessage, messageInfo);
                    if (decrypted != null) {
                        manager.notifyOmemoMessageReceived(decrypted.getBody(), (Message) packet, null, messageInfo);
                    }
                }

            } catch (CryptoFailedException | CorruptedOmemoKeyException | InterruptedException | SmackException.NotConnectedException | XMPPException.XMPPErrorException | SmackException.NoResponseException e) {
                LOGGER.log(Level.WARNING, "internal omemoMessageListener failed to decrypt incoming OMEMO message: "
                        +e.getMessage());

            } catch (NoRawSessionException e) {
                try {
                    OmemoDevice device = new OmemoDevice(sender, omemoMessage.getHeader().getSid());
                    LOGGER.log(Level.INFO, "Received message with invalid session from " +
                            device + ". Send RatchetUpdateMessage.");
                    service.sendOmemoRatchetUpdateMessage(manager, device, true);

                } catch (UndecidedOmemoIdentityException | CorruptedOmemoKeyException | CannotEstablishOmemoSessionException | CryptoFailedException e1) {
                    LOGGER.log(Level.WARNING, "internal omemoMessageListener failed to establish a session for incoming OMEMO message: "
                            +e.getMessage());
                }
            }
        }
    }

    private class OmemoCarbonCopyListener implements CarbonCopyReceivedListener {

        private OmemoManager manager;
        private OmemoService<T_IdKeyPair, T_IdKey, T_PreKey, T_SigPreKey, T_Sess, T_Addr, T_ECPub, T_Bundle, T_Ciph> service;
        private StanzaFilter filter;

        public OmemoCarbonCopyListener(OmemoManager manager,
                                       OmemoService<T_IdKeyPair, T_IdKey, T_PreKey, T_SigPreKey, T_Sess, T_Addr, T_ECPub, T_Bundle, T_Ciph> service,
                                       StanzaFilter filter) {
            this.manager = manager;
            this.service = service;
            this.filter = filter;
        }

        @Override
        public void onCarbonCopyReceived(CarbonExtension.Direction direction, Message carbonCopy, Message wrappingMessage) {
            if (filter.accept(carbonCopy)) {
                BareJid sender = service.getSenderBareJidFromMucMessage(manager, carbonCopy);
                Message decrypted;
                MultiUserChatManager mucm = MultiUserChatManager.getInstanceFor(manager.getConnection());
                OmemoVAxolotlElement omemoMessageElement = carbonCopy.getExtension(OmemoElement.ENCRYPTED, OMEMO_NAMESPACE_V_AXOLOTL);
                OmemoMessageInformation messageInfo = new OmemoMessageInformation();

                if (CarbonExtension.Direction.received.equals(direction)) {
                    messageInfo.setCarbon(OmemoMessageInformation.CARBON.RECV);
                } else {
                    messageInfo.setCarbon(OmemoMessageInformation.CARBON.SENT);
                }

                try {
                    //Is it a MUC message...
                    if (sender != null) {
                        MultiUserChat muc = mucm.getMultiUserChat(carbonCopy.getFrom().asEntityBareJidIfPossible());
                        decrypted = service.processReceivingMessage(manager, sender, omemoMessageElement, messageInfo);

                        if (decrypted != null) {
                            manager.notifyOmemoMucMessageReceived(muc, sender, decrypted.getBody(), carbonCopy, wrappingMessage, messageInfo);
                        }
                    }
                    //... or a normal chat message...
                    else {
                        sender = carbonCopy.getFrom().asBareJid();
                        decrypted = service.processReceivingMessage(manager, sender, omemoMessageElement, messageInfo);

                        if (decrypted != null) {
                            manager.notifyOmemoMessageReceived(decrypted.getBody(), carbonCopy, wrappingMessage, messageInfo);
                        }

                    }
                } catch (CryptoFailedException | CorruptedOmemoKeyException | InterruptedException | SmackException.NotConnectedException | XMPPException.XMPPErrorException | SmackException.NoResponseException e) {
                    LOGGER.log(Level.WARNING, "internal omemoCarbonMessageListener failed to decrypt incoming OMEMO carbon copy: "
                            +e.getMessage());

                } catch (NoRawSessionException e) {
                    try {
                        OmemoDevice device = new OmemoDevice(sender, omemoMessageElement.getHeader().getSid());
                        LOGGER.log(Level.INFO, "Received message with invalid session from " +
                                device + ". Send RatchetUpdateMessage.");
                        service.sendOmemoRatchetUpdateMessage(manager, device, true);

                    } catch (UndecidedOmemoIdentityException | CorruptedOmemoKeyException | CannotEstablishOmemoSessionException | CryptoFailedException e1) {
                        LOGGER.log(Level.WARNING, "internal omemoCarbonMessageListener failed to establish a session for incoming OMEMO carbon copy: "
                                +e.getMessage());
                    }
                }
            }
        }
    }
}
