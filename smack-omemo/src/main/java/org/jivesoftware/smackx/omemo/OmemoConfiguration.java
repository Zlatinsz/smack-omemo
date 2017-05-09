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

import java.io.File;

/**
 * Contains OMEMO related configuration options.
 *
 * @author Paul Schaub
 */
public class OmemoConfiguration {
    private static OmemoConfiguration INSTANCE;

    /**
     * Mitigate vulnerability found in the OMEMO audit.
     * Activate when all clients support it. TODO: Remove this at a later point
     */
    private boolean COMBINED_MESSAGE_KEY_AUTHTAG = true;

    /**
     * Ignore own other stale devices that we did not receive a message from for a period of time.
     * Ignoring means do not encrypt messages for them. This helps to mitigate stale devices that threaten
     * forward secrecy by never advancing ratchets.
     */
    private boolean IGNORE_STALE_DEVICES = true;
    private int IGNORE_STALE_DEVICE_AFTER_HOURS = 24 * 7;         //One week

    /**
     * Delete stale devices from the device list after a period of time.
     */
    private boolean DELETE_STALE_DEVICES = true;
    private int DELETE_STALE_DEVICE_AFTER_HOURS = 24 * 7 * 4;     //4 weeks

    /**
     * Upload a new signed prekey in intervals. This improves forward secrecy. Old keys are kept for some more time and
     * then deleted.
     */
    private boolean RENEW_OLD_SIGNED_PREKEYS = false;
    private int RENEW_OLD_SIGNED_PREKEYS_AFTER_HOURS = 24 * 7;    //One week
    private int MAX_NUMBER_OF_STORED_SIGNED_PREKEYS = 4;

    /**
     * Add a plaintext body hint about omemo encryption to the message.
     */
    private boolean ADD_OMEMO_HINT_BODY = true;

    /**
     * Add Explicit Message Encryption hint (XEP-0380) to the message.
     */
    private boolean ADD_EME_ENCRYPTION_HINT = true;

    /**
     * Add MAM storage hint to allow the server to store messages that do not contain a body.
     */
    private boolean ADD_MAM_STORAGE_HINT = true;

    private File FILE_BASED_OMEMO_STORE_DEFAULT_PATH = null;

    private OmemoConfiguration() {
    }

    public static OmemoConfiguration getInstance() {
        if(INSTANCE == null) {
            INSTANCE = new OmemoConfiguration();
        }
        return INSTANCE;
    }

    public void setIgnoreStaleDevices(boolean ignore) {
        IGNORE_STALE_DEVICES = ignore;
    }

    public boolean getIgnoreStaleDevices() {
        return IGNORE_STALE_DEVICES;
    }

    public void setIgnoreStaleDevicesAfterHours(int hours) {
        IGNORE_STALE_DEVICE_AFTER_HOURS = hours;
    }

    public int getIgnoreStaleDevicesAfterHours() {
        return IGNORE_STALE_DEVICE_AFTER_HOURS;
    }

    public void setDeleteStaleDevices(boolean delete) {
        DELETE_STALE_DEVICES = delete;
    }

    public boolean getDeleteStaleDevices() {
        return DELETE_STALE_DEVICES;
    }

    public void setDeleteStaleDevicesAfterHours(int hours) {
        DELETE_STALE_DEVICE_AFTER_HOURS = hours;
    }

    public int getDeleteStaleDevicesAfterHours() {
        return DELETE_STALE_DEVICE_AFTER_HOURS;
    }

    public void setRenewOldSignedPreKeys(boolean renew) {
        RENEW_OLD_SIGNED_PREKEYS = renew;
    }

    public boolean getRenewOldSignedPreKeys() {
        return RENEW_OLD_SIGNED_PREKEYS;
    }

    public void setRenewOldSignedPreKeysAfterHours(int hours) {
        RENEW_OLD_SIGNED_PREKEYS_AFTER_HOURS = hours;
    }

    public int getRenewOldSignedPreKeysAfterHours() {
        return RENEW_OLD_SIGNED_PREKEYS_AFTER_HOURS;
    }

    public void setMaxNumberOfStoredSignedPreKeys(int number) {
        MAX_NUMBER_OF_STORED_SIGNED_PREKEYS = number;
    }

    public int getMaxNumberOfStoredSignedPreKeys() {
        return MAX_NUMBER_OF_STORED_SIGNED_PREKEYS;
    }

    public void setAddOmemoHintBody(boolean addHint) {
        ADD_OMEMO_HINT_BODY = addHint;
    }

    public boolean getAddOmemoHintBody() {
        return ADD_OMEMO_HINT_BODY;
    }

    public void setAddEmeEncryptionHint(boolean addHint) {
        ADD_EME_ENCRYPTION_HINT = addHint;
    }

    public boolean getAddEmeEncryptionHint() {
        return ADD_EME_ENCRYPTION_HINT;
    }

    public void setAddMAMStorageProcessingHint(boolean addStorageHint) {
        ADD_MAM_STORAGE_HINT = addStorageHint;
    }

    public boolean getAddMAMStorageProcessingHint() {
        return ADD_MAM_STORAGE_HINT;
    }

    public void setHardenMessageEncryption(boolean harden) {
        COMBINED_MESSAGE_KEY_AUTHTAG = harden;
    }

    public boolean getHardenMessageEncryption() {
        return COMBINED_MESSAGE_KEY_AUTHTAG;
    }

    public void setFileBasedOmemoStoreDefaultPath(File path) {
        FILE_BASED_OMEMO_STORE_DEFAULT_PATH = path;
    }

    public File getFileBasedOmemoStoreDefaultPath() {
        return FILE_BASED_OMEMO_STORE_DEFAULT_PATH;
    }
}
