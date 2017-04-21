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
package org.jivesoftware.smackx.omemo.util;

/**
 * Some constants related to OMEMO.
 * @author Paul Schaub
 */
public class OmemoConstants {

    // TODO Most of this should probably be static configuration via setters within OmemoManager. To discuss. -Flow
    //Settings
    /**
     * Mitigate vulnerability found in the OMEMO audit.
     * Activate when all clients support it. TODO: Remove this at a later point
     */
    public static boolean APPEND_AUTH_TAG_TO_MESSAGE_KEY = true;

    /**
     * Ignore own other stale devices that we did not receive a message from for a period of time.
     * Ignoring means do not encrypt messages for them. This helps to mitigate stale devices that threaten
     * forward secrecy by never advancing ratchets.
     */
    public static boolean IGNORE_STALE_DEVICES = true;
    public static int IGNORE_STALE_DEVICE_AFTER_HOURS = 24 * 7;         //One week

    /**
     * Delete stale devices from the device list after a period of time.
     */
    public static boolean DELETE_STALE_DEVICES = true;
    public static int DELETE_STALE_DEVICE_AFTER_HOURS = 24 * 7 * 4;     //4 weeks

    /**
     * Upload a new signed prekey in intervals. This improves forward secrecy. Old keys are kept for some more time and
     * then deleted.
     */
    public static boolean RENEW_OLD_SIGNED_PREKEYS = false;
    public static int RENEW_OLD_SIGNED_PREKEYS_AFTER_HOURS = 24 * 7;    //One week
    public static int MAX_NUMBER_OF_STORED_SIGNED_PREKEYS = 4;

    /**
     * Add a plaintext body hint about omemo encryption to the message.
     */
    public static boolean ADD_OMEMO_HINT_BODY = true;

    /**
     * Add Explicit Message Encryption hint (XEP-0380) to the message.
     */
    public static boolean ADD_EME_ENCRYPTION_HINT = true;

    /**
     * Add MAM storage hint to allow the server to store messages that do not contain a body.
     */
    public static boolean ADD_MAM_STORAGE_HINT = true;

    //Constants
    /**
     * Omemo related namespace.
     */
    public static final String OMEMO_NAMESPACE = "eu.siacs.conversations.axolotl";
    public static final String OMEMO = "OMEMO";

    //PubSub Node names
    public static final String PEP_NODE_DEVICE_LIST = OMEMO_NAMESPACE + ".devicelist";
    public static final String PEP_NODE_DEVICE_LIST_NOTIFY = PEP_NODE_DEVICE_LIST + "+notify";
    public static final String PEP_NODE_BUNDLES = OMEMO_NAMESPACE + ".bundles";

    /**
     * How many preKeys do we want to publish?
     */
    public static final int TARGET_PRE_KEY_COUNT = 100;

    public static final int TYPE_OMEMO_PREKEY_MESSAGE = 1;
    public static final int TYPE_OMEMO_MESSAGE = 0;

    /**
     * Return the node name of the PEP node containing the device bundle of the device with device id deviceId.
     *
     * @param deviceId id of the device
     * @return node name of the devices bundle node
     */
    // TODO should be a private static method in PubSubHelper -Flow
    public static String PEP_NODE_BUNDLE_FROM_DEVICE_ID(int deviceId) {
        return PEP_NODE_BUNDLES + ":" + deviceId;
    }

    public static final String BODY_OMEMO_HINT = "I sent you an OMEMO encrypted message but your client doesn’t seem to support that. Find more information on https://conversations.im/omemo";

    /**
     * Information about the keys used for message encryption.
     */
    public static class Crypto {
        public static final String KEYTYPE = "AES";
        public static final String CIPHERMODE = "AES/GCM/NoPadding";
        public static final String PROVIDER = "BC";
    }
}
