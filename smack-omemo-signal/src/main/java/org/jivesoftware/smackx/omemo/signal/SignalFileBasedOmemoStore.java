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

import org.jivesoftware.smackx.omemo.FileBasedOmemoStore;
import org.jivesoftware.smackx.omemo.OmemoManager;
import org.jivesoftware.smackx.omemo.util.KeyUtil;
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

import java.io.File;
import java.util.List;

/**
 * Implementation of a FileBasedOmemoStore for the smack-omemo-signal module.
 *
 * @author Paul Schaub
 */
public class SignalFileBasedOmemoStore
        extends FileBasedOmemoStore<IdentityKeyPair, IdentityKey, PreKeyRecord, SignedPreKeyRecord, SessionRecord, SignalProtocolAddress, ECPublicKey, PreKeyBundle, SessionCipher>
        implements IdentityKeyStore, SessionStore, PreKeyStore, SignedPreKeyStore {

    private final SignalStoreAdapter signalStoreAdapter = new SignalStoreAdapter(this);

    public SignalFileBasedOmemoStore(OmemoManager manager, File base) {
        super(manager, base);
    }

    @Override
    public KeyUtil<IdentityKeyPair, IdentityKey, PreKeyRecord, SignedPreKeyRecord, SessionRecord, SignalProtocolAddress, ECPublicKey, PreKeyBundle, SessionCipher> keyUtil() {
        return new SignalOmemoKeyUtil();
    }

    @Override
    public List<SignedPreKeyRecord> loadSignedPreKeys() {
        return signalStoreAdapter.loadSignedPreKeys();
    }

    @Override
    public boolean isTrustedIdentity(SignalProtocolAddress signalProtocolAddress, IdentityKey identityKey) {
        return signalStoreAdapter.isTrustedIdentity(signalProtocolAddress, identityKey);
    }

    @Override
    public SessionRecord loadSession(SignalProtocolAddress signalProtocolAddress) {
        return signalStoreAdapter.loadSession(signalProtocolAddress);
    }

    @Override
    public List<Integer> getSubDeviceSessions(String s) {
        return signalStoreAdapter.getSubDeviceSessions(s);
    }

    @Override
    public void deleteSession(SignalProtocolAddress signalProtocolAddress) {
        signalStoreAdapter.deleteSession(signalProtocolAddress);
    }

    @Override
    public boolean containsSession(SignalProtocolAddress signalProtocolAddress) {
        return signalStoreAdapter.containsSession(signalProtocolAddress);
    }

    @Override
    public void deleteAllSessions(String s) {
        signalStoreAdapter.deleteAllSessions(s);
    }

    @Override
    public void storeSession(SignalProtocolAddress signalProtocolAddress, SessionRecord sessionRecord) {
        signalStoreAdapter.storeSession(signalProtocolAddress, sessionRecord);
    }

    @Override
    public IdentityKeyPair getIdentityKeyPair() {
        return signalStoreAdapter.getIdentityKeyPair();
    }

    @Override
    public int getLocalRegistrationId() {
        return signalStoreAdapter.getLocalRegistrationId();
    }

    @Override
    public void saveIdentity(SignalProtocolAddress signalProtocolAddress, IdentityKey identityKey) {
        signalStoreAdapter.saveIdentity(signalProtocolAddress, identityKey);
    }

    @Override
    public PreKeyRecord loadPreKey(int i) throws InvalidKeyIdException {
        return signalStoreAdapter.loadPreKey(i);
    }

    @Override
    public void storePreKey(int i, PreKeyRecord preKeyRecord) {
        signalStoreAdapter.storePreKey(i, preKeyRecord);
    }

    @Override
    public boolean containsPreKey(int i) {
        return signalStoreAdapter.containsPreKey(i);
    }

    @Override
    public void removePreKey(int i) {
        signalStoreAdapter.removePreKey(i);
    }

    @Override
    public SignedPreKeyRecord loadSignedPreKey(int i) throws InvalidKeyIdException {
        return signalStoreAdapter.loadSignedPreKey(i);
    }

    @Override
    public void storeSignedPreKey(int i, SignedPreKeyRecord signedPreKeyRecord) {
        signalStoreAdapter.storeSignedPreKey(i, signedPreKeyRecord);
    }

    @Override
    public boolean containsSignedPreKey(int i) {
        return signalStoreAdapter.containsSignedPreKey(i);
    }

    @Override
    public void removeSignedPreKey(int i) {
        signalStoreAdapter.removeSignedPreKey(i);
    }

}
