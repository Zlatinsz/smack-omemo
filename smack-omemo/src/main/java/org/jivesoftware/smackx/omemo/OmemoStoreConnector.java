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

import org.jivesoftware.smack.roster.Roster;
import org.jivesoftware.smack.roster.RosterEntry;
import org.jivesoftware.smackx.omemo.elements.OmemoBundleVAxolotlElement;
import org.jivesoftware.smackx.omemo.elements.OmemoDeviceListElement;
import org.jivesoftware.smackx.omemo.exceptions.CannotEstablishOmemoSessionException;
import org.jivesoftware.smackx.omemo.exceptions.CorruptedOmemoKeyException;
import org.jivesoftware.smackx.omemo.internal.CachedDeviceList;
import org.jivesoftware.smackx.omemo.internal.OmemoDevice;
import org.jivesoftware.smackx.omemo.internal.OmemoSession;
import org.jivesoftware.smackx.omemo.util.KeyUtil;
import org.jxmpp.jid.BareJid;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

import static org.jivesoftware.smackx.omemo.util.OmemoConstants.TARGET_PRE_KEY_COUNT;

/**
 * Adapt a library store to the OmemoStore.
 */
public class OmemoStoreConnector<T_IdKeyPair, T_IdKey, T_PreKey, T_SigPreKey, T_Sess, T_Addr, T_ECPub, T_Bundle, T_Ciph> {

    private final Logger LOGGER = Logger.getLogger(OmemoStoreConnector.class.getSimpleName());

    protected final OmemoManager omemoManager;
    protected final OmemoStore<T_IdKeyPair, T_IdKey, T_PreKey, T_SigPreKey, T_Sess, T_Addr, T_ECPub, T_Bundle, T_Ciph>
            omemoStore;
    protected HashMap<OmemoDevice, OmemoSession<T_IdKeyPair, T_IdKey, T_PreKey, T_SigPreKey, T_Sess, T_Addr, T_ECPub, T_Bundle, T_Ciph>>
            omemoSessions = new HashMap<>();

    public OmemoStoreConnector(OmemoManager omemoManager, OmemoStore<T_IdKeyPair, T_IdKey, T_PreKey, T_SigPreKey, T_Sess, T_Addr, T_ECPub, T_Bundle, T_Ciph> omemoStore) {
        this.omemoManager = omemoManager;
        this.omemoStore = omemoStore;
    }

    public boolean isFreshInstallation() {
        return omemoStore.isFreshInstallation(omemoManager);
    }

    /**
     * Generate a new Identity (deviceId, identityKeys, preKeys...).
     *
     * @throws CorruptedOmemoKeyException in case something goes wrong
     */
    void regenerate() throws CorruptedOmemoKeyException {
        LOGGER.log(Level.INFO, "Regenerating...");
        int nextPreKeyId = 1;
        storeOmemoIdentityKeyPair(generateOmemoIdentityKeyPair());
        storeOmemoPreKeys(generateOmemoPreKeys(nextPreKeyId, TARGET_PRE_KEY_COUNT));
        storeLastPreKeyId(keyUtil().addInBounds(nextPreKeyId, TARGET_PRE_KEY_COUNT));
        storeCurrentSignedPreKeyId(-1); //Set back to no-value default
        changeSignedPreKey();
    }

    void mergeCachedDeviceList(BareJid contact, OmemoDeviceListElement list) {
        omemoStore.mergeCachedDeviceList(omemoManager, contact, list);
    }

    void changeSignedPreKey() throws CorruptedOmemoKeyException {
        omemoStore.changeSignedPreKey(omemoManager);
    }

    boolean isAvailableDeviceId(int id) {
        return omemoStore.isAvailableDeviceId(omemoManager, id);
    }

    public int loadLastPreKeyId() {
        return omemoStore.loadLastPreKeyId(omemoManager);
    }

    public void storeLastPreKeyId(int currentPreKeyId) {
        omemoStore.storeLastPreKeyId(omemoManager, currentPreKeyId);
    }

    /**
     * Generate a new IdentityKeyPair. We should always have only one pair and usually keep this for a long time.
     *
     * @return identityKeyPair
     */
    T_IdKeyPair generateOmemoIdentityKeyPair() {
        return omemoStore.generateOmemoIdentityKeyPair();
    }

    public T_IdKeyPair loadOmemoIdentityKeyPair() throws CorruptedOmemoKeyException {
        return omemoStore.loadOmemoIdentityKeyPair(omemoManager);
    }

    public void storeOmemoIdentityKeyPair(T_IdKeyPair identityKeyPair) {
        omemoStore.storeOmemoIdentityKeyPair(omemoManager, identityKeyPair);
    }

    public T_IdKey loadOmemoIdentityKey(OmemoDevice device) throws CorruptedOmemoKeyException {
        return omemoStore.loadOmemoIdentityKey(omemoManager, device);
    }

    public void storeOmemoIdentityKey(OmemoDevice device, T_IdKey t_idKey) {
        omemoStore.storeOmemoIdentityKey(omemoManager, device, t_idKey);
    }

    public boolean isTrustedOmemoIdentity(OmemoDevice device, T_IdKey identityKey) {
        return omemoStore.isTrustedOmemoIdentity(omemoManager, device, identityKey);
    }

    public boolean isDecidedOmemoIdentity(OmemoDevice device, T_IdKey identityKey) {
        return omemoStore.isDecidedOmemoIdentity(omemoManager, device, identityKey);
    }

    public void trustOmemoIdentity(OmemoDevice device, T_IdKey identityKey) {
        omemoStore.trustOmemoIdentity(omemoManager, device, identityKey);
    }

    public void distrustOmemoIdentity(OmemoDevice device, T_IdKey identityKey) {
        omemoStore.distrustOmemoIdentity(omemoManager, device, identityKey);
    }

    public void setDateOfLastReceivedMessage(OmemoDevice from, Date date) {
        omemoStore.setDateOfLastReceivedMessage(omemoManager, from, date);
    }

    public void setDateOfLastReceivedMessage(OmemoDevice from) {
        omemoStore.setDateOfLastReceivedMessage(omemoManager, from);
    }

    public Date getDateOfLastReceivedMessage(OmemoDevice from) {
        return omemoStore.getDateOfLastReceivedMessage(omemoManager, from);
    }

    public void setDateOfLastSignedPreKeyRenewal(Date date) {
        omemoStore.setDateOfLastSignedPreKeyRenewal(omemoManager, date);
    }

    public void setDateOfLastSignedPreKeyRenewal() {
        setDateOfLastSignedPreKeyRenewal(new Date());
    }

    public Date getDateOfLastSignedPreKeyRenewal() {
        return omemoStore.getDateOfLastSignedPreKeyRenewal(omemoManager);
    }

    OmemoBundleVAxolotlElement packOmemoBundle() throws CorruptedOmemoKeyException {
        return omemoStore.packOmemoBundle(omemoManager);
    }

    public HashMap<Integer, T_PreKey> generateOmemoPreKeys(int startId, int count) {
        return omemoStore.generateOmemoPreKeys(startId, count);
    }

    public T_PreKey loadOmemoPreKey(int preKeyId) {
        return omemoStore.loadOmemoPreKey(omemoManager, preKeyId);
    }

    public void storeOmemoPreKey(int preKeyId, T_PreKey t_preKey) {
        omemoStore.storeOmemoPreKey(omemoManager, preKeyId, t_preKey);
    }

    public void storeOmemoPreKeys(HashMap<Integer, T_PreKey> preKeyHashMap) {
        omemoStore.storeOmemoPreKeys(omemoManager, preKeyHashMap);
    }

    public void removeOmemoPreKey(int preKeyId) {
        omemoStore.removeOmemoPreKey(omemoManager, preKeyId);
    }

    public int loadCurrentSignedPreKeyId() {
        return omemoStore.loadCurrentSignedPreKeyId(omemoManager);
    }

    public void storeCurrentSignedPreKeyId(int currentSignedPreKeyId) {
        omemoStore.storeCurrentSignedPreKeyId(omemoManager, currentSignedPreKeyId);
    }

    public HashMap<Integer, T_PreKey> loadOmemoPreKeys() {
        return omemoStore.loadOmemoPreKeys(omemoManager);
    }

    public T_SigPreKey loadOmemoSignedPreKey(int signedPreKeyId) {
        return omemoStore.loadOmemoSignedPreKey(omemoManager, signedPreKeyId);
    }

    public HashMap<Integer, T_SigPreKey> loadOmemoSignedPreKeys() {
        return omemoStore.loadOmemoSignedPreKeys(omemoManager);
    }

    public void storeOmemoSignedPreKey(int signedPreKeyId, T_SigPreKey signedPreKey) {
        omemoStore.storeOmemoSignedPreKey(omemoManager, signedPreKeyId, signedPreKey);
    }

    public void removeOmemoSignedPreKey(int signedPreKeyId) {
        omemoStore.removeOmemoSignedPreKey(omemoManager, signedPreKeyId);
    }

    public T_Sess loadRawSession(OmemoDevice device) {
        return omemoStore.loadRawSession(omemoManager, device);
    }

    public HashMap<Integer, T_Sess> loadAllRawSessionsOf(BareJid contact) {
        return omemoStore.loadAllRawSessionsOf(omemoManager, contact);
    }

    public void storeRawSession(OmemoDevice device, T_Sess session) {
        omemoStore.storeRawSession(omemoManager, device, session);
    }

    public void removeRawSession(OmemoDevice device) {
        omemoStore.removeRawSession(omemoManager, device);
    }

    public void removeAllRawSessionsOf(BareJid contact) {
        omemoStore.removeAllRawSessionsOf(omemoManager, contact);
    }

    public boolean containsRawSession(OmemoDevice device) {
        return omemoStore.containsRawSession(omemoManager, device);
    }

    public CachedDeviceList loadCachedDeviceList(BareJid contact) {
        return omemoStore.loadCachedDeviceList(omemoManager, contact);
    }

    public void storeCachedDeviceList(BareJid contact, CachedDeviceList deviceList) {
        omemoStore.storeCachedDeviceList(omemoManager, contact, deviceList);
    }

    public void purgeOwnDeviceKeys() {
        omemoStore.purgeOwnDeviceKeys(omemoManager);
    }

    /**
     * Preload all OMEMO sessions for our devices and our contacts.
     */
    void initializeOmemoSessions() {
        BareJid ownJid = omemoManager.getConnection().getUser().asBareJid();
        HashMap<Integer, T_Sess> ourDevices = loadAllRawSessionsOf(ownJid);
        ourDevices.remove(omemoManager.getDeviceId());

        omemoSessions.putAll(buildOmemoSessionsFor(ownJid, ourDevices));
        for (RosterEntry rosterEntry : Roster.getInstanceFor(omemoManager.getConnection()).getEntries()) {
            HashMap<Integer, T_Sess> contactDevices = loadAllRawSessionsOf(rosterEntry.getJid().asBareJid());
            omemoSessions.putAll(buildOmemoSessionsFor(rosterEntry.getJid().asBareJid(), contactDevices));
        }
    }

    /**
     * Create a new concrete OmemoSession with a contact.
     *
     * @param device      device to establish the session with
     * @param identityKey identityKey of the device
     * @return concrete OmemoSession
     */
    public OmemoSession<T_IdKeyPair, T_IdKey, T_PreKey, T_SigPreKey, T_Sess, T_Addr, T_ECPub, T_Bundle, T_Ciph>
    createOmemoSession(OmemoDevice device, T_IdKey identityKey) {
        return keyUtil().createOmemoSession(this, device, identityKey);
    }

    /**
     * Return the OmemoSession for the OmemoDevice.
     *
     * @param device OmemoDevice
     * @return OmemoSession
     */
    public OmemoSession<T_IdKeyPair, T_IdKey, T_PreKey, T_SigPreKey, T_Sess, T_Addr, T_ECPub, T_Bundle, T_Ciph>
    getOmemoSessionOf(OmemoDevice device) {
        OmemoSession<T_IdKeyPair, T_IdKey, T_PreKey, T_SigPreKey, T_Sess, T_Addr, T_ECPub, T_Bundle, T_Ciph>
                session = omemoSessions.get(device);
        if (session == null) {
            T_IdKey identityKey = null;
            try {
                identityKey = loadOmemoIdentityKey(device);
            } catch (CorruptedOmemoKeyException e) {
                LOGGER.log(Level.WARNING, "getOmemoSessionOf could not load identityKey of "+device+": "+e.getMessage());
            }

            if (identityKey != null) {
                session = createOmemoSession(device, identityKey);

            } else {
                LOGGER.log(Level.INFO, "getOmemoSessionOf couldn't find an identityKey for "+device
                        +". Initiate session without.");
                session = createOmemoSession(device, null);
            }

            omemoSessions.put(device, session);
        }

        if(session.getIdentityKey() == null) {
            try {
                session.setIdentityKey(loadOmemoIdentityKey(device));
            } catch (CorruptedOmemoKeyException e) {
                LOGGER.log(Level.WARNING, "Can't update IdentityKey of "+device+": "+e.getMessage());
            }
        }
        return session;
    }

    /**
     * Create OmemoSession objects for all T_Sess objects of the contact.
     * The T_Sess objects will be wrapped inside a OmemoSession for every device of the contact.
     *
     * @param contact     BareJid of the contact
     * @param rawSessions HashMap of Integers (deviceIds) and T_Sess sessions.
     * @return HashMap of OmemoContacts and OmemoSessions
     */
    private HashMap<OmemoDevice, OmemoSession<T_IdKeyPair, T_IdKey, T_PreKey, T_SigPreKey, T_Sess, T_Addr, T_ECPub, T_Bundle, T_Ciph>>
    buildOmemoSessionsFor(BareJid contact, HashMap<Integer, T_Sess> rawSessions) {

        HashMap<OmemoDevice, OmemoSession<T_IdKeyPair, T_IdKey, T_PreKey, T_SigPreKey, T_Sess, T_Addr, T_ECPub, T_Bundle, T_Ciph>>
                sessions = new HashMap<>();

        for (Map.Entry<Integer, T_Sess> e : rawSessions.entrySet()) {
            OmemoDevice omemoDevice = new OmemoDevice(contact, e.getKey());
            try {
                T_IdKey identityKey = loadOmemoIdentityKey(omemoDevice);
                if(identityKey != null) {
                    sessions.put(omemoDevice, createOmemoSession(omemoDevice, identityKey));
                } else {
                    LOGGER.log(Level.WARNING, "IdentityKey of "+omemoDevice+" is null");
                }
            } catch (CorruptedOmemoKeyException e1) {
                LOGGER.log(Level.WARNING, "buildOmemoSessionFor could not create a session for "+omemoDevice+
                        ": "+e1.getMessage());
            }
        }
        return sessions;
    }


    public KeyUtil<T_IdKeyPair, T_IdKey, T_PreKey, T_SigPreKey, T_Sess, T_Addr, T_ECPub, T_Bundle, T_Ciph> keyUtil() {
        return omemoStore.keyUtil();
    }

    public OmemoStore<T_IdKeyPair, T_IdKey, T_PreKey, T_SigPreKey, T_Sess, T_Addr, T_ECPub, T_Bundle, T_Ciph>
    getOmemoStore() {
        return omemoStore;
    }

    public String getFingerprint() {
        return omemoStore.getFingerprint(omemoManager);
    }

    public String getFingerprint(OmemoDevice device) throws CannotEstablishOmemoSessionException {
        return omemoStore.getFingerprint(omemoManager, device);
    }
}
