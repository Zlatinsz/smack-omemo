/**
 *
 * Copyright 2017 Florian Schmaus, Paul Schaub
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

import org.igniterealtime.smack.inttest.AbstractSmackIntegrationTest;
import org.igniterealtime.smack.inttest.SmackIntegrationTest;
import org.igniterealtime.smack.inttest.SmackIntegrationTestEnvironment;
import org.igniterealtime.smack.inttest.TestNotPossibleException;
import org.jivesoftware.smack.SmackException;
import org.jivesoftware.smack.XMPPException;
import org.jivesoftware.smackx.omemo.elements.OmemoBundleElement;
import org.jivesoftware.smackx.omemo.exceptions.CorruptedOmemoKeyException;
import org.jivesoftware.smackx.omemo.util.OmemoConstants;
import org.jivesoftware.smackx.pubsub.PubSubException;
import org.jivesoftware.smackx.pubsub.PubSubManager;

import java.io.File;
import java.util.logging.Level;

import static junit.framework.TestCase.assertEquals;
import static junit.framework.TestCase.assertNotNull;
import static junit.framework.TestCase.assertTrue;

@SuppressWarnings("unused")
public class OmemoIntegrationTest extends AbstractSmackIntegrationTest {

    private static final File storePath = new File("int_test_omemo_store");
    private static final int deviceId = 123456789;

    public OmemoIntegrationTest(SmackIntegrationTestEnvironment environment) throws TestNotPossibleException {
        super(environment);
        if (!OmemoService.isServiceRegistered()) {
            throw new TestNotPossibleException("No OmemoService registered");
        }
        cleanUpStore();
        OmemoConfiguration.getInstance().setFileBasedOmemoStoreDefaultPath(storePath);

        //Test for server support
        try {
            if(!OmemoManager.serverSupportsOmemo(connection, connection.getXMPPServiceDomain())) {
                throw new TestNotPossibleException("Server does not support OMEMO");
            } else {
                LOGGER.log(Level.INFO, "Server supports OMEMO :)");
            }
        } catch (XMPPException.XMPPErrorException | SmackException.NoResponseException | InterruptedException | SmackException.NotConnectedException e) {
            throw new TestNotPossibleException("Cannot determine, whether server supports OMEMO: "+e.getMessage());
        }
    }

    /**
     * Tests, if the initialization is done properly.
     */
    @SmackIntegrationTest
    public void initializationTest() throws XMPPException.XMPPErrorException, PubSubException.NotALeafNodeException, SmackException.NotConnectedException, InterruptedException, SmackException.NoResponseException, SmackException.NotLoggedInException, CorruptedOmemoKeyException {
        //Make sure we start fresh
        FileBasedOmemoStoreV2.deleteRecursively(storePath);

        OmemoManager omemoManager = OmemoManager.getInstanceFor(conOne, deviceId);
        OmemoStore<?,?,?,?,?,?,?,?,?> omemoStore = omemoManager.getOmemoService().getOmemoStoreBackend();

        //test keys.
        omemoManager.initialize();
        assertNotNull("IdentityKey must not be null after initialization.", omemoStore.loadOmemoIdentityKeyPair(omemoManager));
        assertTrue("We must have "+OmemoConstants.TARGET_PRE_KEY_COUNT+" preKeys.",
                omemoStore.loadOmemoPreKeys(omemoManager).size() == OmemoConstants.TARGET_PRE_KEY_COUNT);
        assertNotNull("Our signedPreKey must not be null.", omemoStore.loadCurrentSignedPreKeyId(omemoManager));

        //Is deviceId published?
        assertTrue("Published deviceList must contain our deviceId.",
                omemoManager.getOmemoService().fetchDeviceList(omemoManager, conOne.getUser().asBareJid())
                .getDeviceIds().contains(deviceId));

        //Did we publish our bundle?
        OmemoBundleElement ourBundle = omemoStore.packOmemoBundle(omemoManager);
        assertNotNull("Our bundle must not be null.",ourBundle);
        assertEquals("Our bundle must be published.", ourBundle,
                omemoManager.getOmemoService().fetchBundle(omemoManager, omemoManager.getOwnDevice()));

        //clean up
        cleanUpStore();
        cleanUpPubSub(omemoManager);
    }

    private void cleanUpStore() {
        FileBasedOmemoStoreV2.deleteRecursively(storePath);
    }

    private void cleanUpPubSub(OmemoManager omemoManager) {
        PubSubManager pm = PubSubManager.getInstance(omemoManager.getConnection(),omemoManager.getOwnJid());
        try {
            pm.deleteNode(OmemoConstants.PEP_NODE_BUNDLE_FROM_DEVICE_ID(deviceId));
            pm.deleteNode(OmemoConstants.PEP_NODE_DEVICE_LIST);
        } catch (SmackException.NoResponseException | InterruptedException | SmackException.NotConnectedException | XMPPException.XMPPErrorException e) {
            LOGGER.log(Level.WARNING, "Exception while deleting used OMEMO PubSub node: "+e.getMessage());
        }
    }
}
