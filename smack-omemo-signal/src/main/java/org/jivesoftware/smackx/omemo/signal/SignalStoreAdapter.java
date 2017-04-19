/**
 *
 * Copyright 2017 Paul Schaub
 *
 * This file is part of smack-omemo-signal.
 *
 * smack-omemo-signal is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
 */
package org.jivesoftware.smackx.omemo.signal;

import org.jivesoftware.smackx.omemo.OmemoStore;
import org.jivesoftware.smackx.omemo.exceptions.CorruptedOmemoKeyException;
import org.jxmpp.jid.impl.JidCreate;
import org.jxmpp.stringprep.XmppStringprepException;
import org.whispersystems.libsignal.IdentityKey;
import org.whispersystems.libsignal.IdentityKeyPair;
import org.whispersystems.libsignal.InvalidKeyIdException;
import org.whispersystems.libsignal.SessionCipher;
import org.whispersystems.libsignal.SignalProtocolAddress;
import org.whispersystems.libsignal.ecc.ECPublicKey;
import org.whispersystems.libsignal.state.IdentityKeyStore;
import org.whispersystems.libsignal.state.PreKeyBundle;
import org.whispersystems.libsignal.state.PreKeyRecord;
import org.whispersystems.libsignal.state.PreKeyStore;
import org.whispersystems.libsignal.state.SessionRecord;
import org.whispersystems.libsignal.state.SessionStore;
import org.whispersystems.libsignal.state.SignedPreKeyRecord;
import org.whispersystems.libsignal.state.SignedPreKeyStore;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Class that adapts libsignal-protocol-java's Store classes to the OmemoStore class.
 *
 * @author Paul Schaub
 */
public class SignalStoreAdapter implements IdentityKeyStore, SessionStore, PreKeyStore, SignedPreKeyStore {

    private final OmemoStore<IdentityKeyPair, IdentityKey, PreKeyRecord, SignedPreKeyRecord, SessionRecord, SignalProtocolAddress, ECPublicKey, PreKeyBundle, SessionCipher> omemoStore;
    private static final Logger LOGGER = Logger.getLogger(SignalStoreAdapter.class.getName());

    public SignalStoreAdapter(OmemoStore<IdentityKeyPair, IdentityKey, PreKeyRecord, SignedPreKeyRecord, SessionRecord, SignalProtocolAddress, ECPublicKey, PreKeyBundle, SessionCipher> store) {
        this.omemoStore = store;
    }

    @Override
    public IdentityKeyPair getIdentityKeyPair() {
        try {
            return omemoStore.loadOmemoIdentityKeyPair();
        } catch (CorruptedOmemoKeyException e) {
            LOGGER.log(Level.SEVERE, "getIdentityKeyPair has failed: "+ e.getMessage());
            return null;
        }
    }

    @Override
    public int getLocalRegistrationId() {
        return 0;
    }

    @Override
    public void saveIdentity(SignalProtocolAddress signalProtocolAddress, IdentityKey identityKey) {
        try {
            omemoStore.storeOmemoIdentityKey(omemoStore.keyUtil().addressAsOmemoContact(signalProtocolAddress), identityKey);
        } catch (XmppStringprepException e) {
            LOGGER.log(Level.SEVERE, "saveIdentity has failed:" +e.getMessage());
        }
    }

    @Override
    public boolean isTrustedIdentity(SignalProtocolAddress signalProtocolAddress, IdentityKey identityKey) {
        //Disable internal trust management. Instead we use OmemoStore.isTrustedOmemoIdentity() before encrypting for a
        //recipient.
        return true;
    }

    @Override
    public PreKeyRecord loadPreKey(int i) throws InvalidKeyIdException {
        PreKeyRecord pr = omemoStore.loadOmemoPreKey(i);
        if (pr == null) {
            throw new InvalidKeyIdException("No PreKey with Id " + i + " found!");
        }
        return pr;
    }

    @Override
    public void storePreKey(int i, PreKeyRecord preKeyRecord) {
        omemoStore.storeOmemoPreKey(i, preKeyRecord);
    }

    @Override
    public boolean containsPreKey(int i) {
        try {
            return (loadPreKey(i) != null);
        } catch (InvalidKeyIdException e) {
            LOGGER.log(Level.WARNING, "containsPreKey has failed: "+e.getMessage());
            return false;
        }
    }

    @Override
    public void removePreKey(int i) {
        omemoStore.removeOmemoPreKey(i);
    }

    @Override
    public SessionRecord loadSession(SignalProtocolAddress signalProtocolAddress) {
        try {
            SessionRecord s = omemoStore.loadRawSession(omemoStore.keyUtil().addressAsOmemoContact(signalProtocolAddress));
            return (s != null ? s : new SessionRecord());
        } catch (XmppStringprepException e) {
            LOGGER.log(Level.SEVERE, "loadSession has failed: "+e.getMessage());
            return null;
        }
    }

    @Override
    public List<Integer> getSubDeviceSessions(String s) {
        HashMap<Integer, SessionRecord> contactsSessions = null;
        try {
            contactsSessions = omemoStore.loadAllRawSessionsOf(JidCreate.bareFrom(s));
        } catch (XmppStringprepException e) {
            LOGGER.log(Level.WARNING, "getSubDeviceSessions has failed:"+e.getMessage());
        }
        if (contactsSessions != null) {
            return new ArrayList<>(contactsSessions.keySet());
        }
        return new ArrayList<>();
    }

    @Override
    public void storeSession(SignalProtocolAddress signalProtocolAddress, SessionRecord sessionRecord) {
        try {
            omemoStore.storeRawSession(omemoStore.keyUtil().addressAsOmemoContact(signalProtocolAddress), sessionRecord);
        } catch (XmppStringprepException e) {
            LOGGER.log(Level.SEVERE, "storeSession has failed:"+e.getMessage());
        }
    }

    @Override
    public boolean containsSession(SignalProtocolAddress signalProtocolAddress) {
        try {
            return omemoStore.containsRawSession(omemoStore.keyUtil().addressAsOmemoContact(signalProtocolAddress));
        } catch (XmppStringprepException e) {
            LOGGER.log(Level.WARNING, "containsSession has failed: "+e.getMessage());
            return false;
        }
    }

    @Override
    public void deleteSession(SignalProtocolAddress signalProtocolAddress) {
        try {
            omemoStore.removeRawSession(omemoStore.keyUtil().addressAsOmemoContact(signalProtocolAddress));
        } catch (XmppStringprepException e) {
            LOGGER.log(Level.WARNING, "deleteSession has failed: "+e.getMessage());
        }
    }

    @Override
    public void deleteAllSessions(String s) {
        try {
            omemoStore.removeAllRawSessionsOf(JidCreate.bareFrom(s));
        } catch (XmppStringprepException e) {
            LOGGER.log(Level.WARNING, "deleteAllSession has failed: "+e.getMessage());
        }
    }

    @Override
    public SignedPreKeyRecord loadSignedPreKey(int i) throws InvalidKeyIdException {
        SignedPreKeyRecord spkr = omemoStore.loadOmemoSignedPreKey(i);
        if (spkr == null) {
            throw new InvalidKeyIdException("No SignedPreKey with Id " + i + " found!");
        }
        return spkr;
    }

    @Override
    public List<SignedPreKeyRecord> loadSignedPreKeys() {
        HashMap<Integer, SignedPreKeyRecord> signedPreKeyRecordHashMap = omemoStore.loadOmemoSignedPreKeys();
        List<SignedPreKeyRecord> signedPreKeyRecordList = new ArrayList<>();
        signedPreKeyRecordList.addAll(signedPreKeyRecordHashMap.values());
        return signedPreKeyRecordList;
    }

    @Override
    public void storeSignedPreKey(int i, SignedPreKeyRecord signedPreKeyRecord) {
        omemoStore.storeOmemoSignedPreKey(i, signedPreKeyRecord);
    }

    @Override
    public boolean containsSignedPreKey(int i) {
        try {
            return loadSignedPreKey(i) != null;
        } catch (InvalidKeyIdException e) {
            LOGGER.log(Level.WARNING, "containsSignedPreKey has failed: "+e.getMessage());
            return false;
        }
    }

    @Override
    public void removeSignedPreKey(int i) {
        omemoStore.removeOmemoSignedPreKey(i);
    }
}
