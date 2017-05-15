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
import org.jivesoftware.smack.chat2.ChatManager;
import org.jivesoftware.smack.packet.Message;
import org.jivesoftware.smack.roster.Roster;
import org.jivesoftware.smackx.omemo.elements.OmemoBundleElement;
import org.jivesoftware.smackx.omemo.exceptions.CannotEstablishOmemoSessionException;
import org.jivesoftware.smackx.omemo.exceptions.CorruptedOmemoKeyException;
import org.jivesoftware.smackx.omemo.exceptions.CryptoFailedException;
import org.jivesoftware.smackx.omemo.exceptions.UndecidedOmemoIdentityException;
import org.jivesoftware.smackx.omemo.internal.CipherAndAuthTag;
import org.jivesoftware.smackx.omemo.internal.OmemoMessageInformation;
import org.jivesoftware.smackx.omemo.listener.OmemoMessageListener;
import org.jivesoftware.smackx.omemo.util.OmemoConstants;
import org.jivesoftware.smackx.pubsub.PubSubException;
import org.jivesoftware.smackx.pubsub.PubSubManager;

import java.io.File;
import java.security.NoSuchAlgorithmException;
import java.util.logging.Level;

import static junit.framework.TestCase.assertEquals;
import static junit.framework.TestCase.assertNotNull;
import static junit.framework.TestCase.assertTrue;

@SuppressWarnings("unused")
public class OmemoIntegrationTest extends AbstractSmackIntegrationTest {

    private static final File storePath = new File("int_test_omemo_store");

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
    //@SmackIntegrationTest
    public  void initializationTest() throws XMPPException.XMPPErrorException, PubSubException.NotALeafNodeException, SmackException.NotConnectedException, InterruptedException, SmackException.NoResponseException, SmackException.NotLoggedInException, CorruptedOmemoKeyException {
        //Make sure we start fresh
        cleanUpStore();

        OmemoManager omemoManager = OmemoManager.getInstanceFor(conThree, 666);
        OmemoStore<?,?,?,?,?,?,?,?,?> omemoStore = omemoManager.getOmemoService().getOmemoStoreBackend();

        //test keys.
        omemoManager.initialize();
        assertNotNull("IdentityKey must not be null after initialization.", omemoStore.loadOmemoIdentityKeyPair(omemoManager));
        assertTrue("We must have "+OmemoConstants.TARGET_PRE_KEY_COUNT+" preKeys.",
                omemoStore.loadOmemoPreKeys(omemoManager).size() == OmemoConstants.TARGET_PRE_KEY_COUNT);
        assertNotNull("Our signedPreKey must not be null.", omemoStore.loadCurrentSignedPreKeyId(omemoManager));

        //Is deviceId published?
        assertTrue("Published deviceList must contain our deviceId.",
                omemoManager.getOmemoService().fetchDeviceList(omemoManager, conThree.getUser().asBareJid())
                .getDeviceIds().contains(omemoManager.getDeviceId()));

        //Did we publish our bundle?
        OmemoBundleElement ourBundle = omemoStore.packOmemoBundle(omemoManager);
        assertNotNull("Our bundle must not be null.",ourBundle);
        assertEquals("Our bundle must be published.", ourBundle,
                omemoManager.getOmemoService().fetchBundle(omemoManager, omemoManager.getOwnDevice()));

        //clean up
        cleanUpStore();
        cleanUpPubSub(omemoManager);
    }

    /**
     * This test sends an encrypted message from alice to bob.
     * @throws CorruptedOmemoKeyException
     * @throws InterruptedException
     * @throws SmackException.NoResponseException
     * @throws SmackException.NotConnectedException
     * @throws XMPPException.XMPPErrorException
     * @throws SmackException.NotLoggedInException
     * @throws PubSubException.NotALeafNodeException
     * @throws CannotEstablishOmemoSessionException
     * @throws UndecidedOmemoIdentityException
     * @throws NoSuchAlgorithmException
     * @throws CryptoFailedException
     */
    @SmackIntegrationTest
    public void messageSendingTest() throws CorruptedOmemoKeyException, InterruptedException, SmackException.NoResponseException, SmackException.NotConnectedException, XMPPException.XMPPErrorException, SmackException.NotLoggedInException, PubSubException.NotALeafNodeException, CannotEstablishOmemoSessionException, UndecidedOmemoIdentityException, NoSuchAlgorithmException, CryptoFailedException {
        int aliceId = 123, bobsId = 345;
        final String secretMessage = "This is Alice! Can you here me Bob?";
        final boolean[] success = new boolean[1];    //be pessimistic
        final int maxWaitingSecs = 60;
        int secsWaited = 0;

        cleanUpStore();

        //Get Managers and Stores
        OmemoManager alice = OmemoManager.getInstanceFor(conOne, aliceId);
        OmemoManager bob = OmemoManager.getInstanceFor(conTwo, bobsId);
        OmemoStore<?,?,?,?,?,?,?,?,?> omemoStore = OmemoService.getInstance().getOmemoStoreBackend();

        //initialize OmemoManagers
        alice.initialize();
        bob.initialize();

        //Register messageListeners
        bob.addOmemoMessageListener(new OmemoMessageListener() {
            @Override
            public void onOmemoMessageReceived(String decryptedBody, Message encryptedMessage, Message wrappingMessage, OmemoMessageInformation omemoInformation) {
                LOGGER.log(Level.INFO,"Received message: "+decryptedBody);
                assertEquals(decryptedBody.trim(), secretMessage.trim());
                success[0] = true;
            }

            @Override
            public void onOmemoKeyTransportReceived(CipherAndAuthTag cipherAndAuthTag, Message message, Message wrappingMessage, OmemoMessageInformation omemoInformation) {
            }
        });

        //Subscribe to one another
        Roster aliceRoster = Roster.getInstanceFor(conOne);
        aliceRoster.setSubscriptionMode(Roster.SubscriptionMode.accept_all);
        Roster bobsRoster = Roster.getInstanceFor(conTwo);
        bobsRoster.setSubscriptionMode(Roster.SubscriptionMode.accept_all);
        aliceRoster.createEntry(bob.getOwnJid(), "bob", null);
        bobsRoster.createEntry(alice.getOwnJid(), "alice", null);

        //Fetch deviceLists
        alice.requestDeviceListUpdateFor(bob.getOwnJid());
        bob.requestDeviceListUpdateFor(alice.getOwnJid());
        assertTrue("Alice must know Bobs device at this point.",
                omemoStore.loadCachedDeviceList(alice, bob.getOwnJid())
                        .getActiveDevices().contains(bob.getDeviceId()));
        assertTrue("Bob must know Alice device at this point.",
                omemoStore.loadCachedDeviceList(bob, alice.getOwnJid())
                        .getActiveDevices().contains(alice.getDeviceId()));

        //Create sessions
        alice.buildSessionsWith(bob.getOwnJid());
        bob.buildSessionsWith(alice.getOwnJid());
        assertTrue("Alice must have a session with Bob at this point.",
                !omemoStore.loadAllRawSessionsOf(alice, bob.getOwnJid()).isEmpty());
        assertTrue("Bob must have a session with Alice at this point.",
                !omemoStore.loadAllRawSessionsOf(bob, alice.getOwnJid()).isEmpty());

        //Trust one another
        omemoStore.trustOmemoIdentity(alice, bob.getOwnDevice(),
                omemoStore.getFingerprint(alice, bob.getOwnDevice()));
        omemoStore.trustOmemoIdentity(bob, alice.getOwnDevice(),
                omemoStore.getFingerprint(bob, alice.getOwnDevice()));

        //Prepare Message
        Message message = new Message(bob.getOwnJid(), secretMessage);
        Message encryptedMessage = alice.encrypt(bob.getOwnJid(), message);

        //Send message
        ChatManager.getInstanceFor(alice.getConnection()).chatWith(bob.getOwnJid().asEntityBareJidIfPossible())
                .send(encryptedMessage);

        while (!success[0] && secsWaited < maxWaitingSecs) {
            secsWaited++;
            Thread.sleep(1000);
        }

        //Clean up
        cleanUpPubSub(alice);
        cleanUpPubSub(bob);

        cleanUpStore();

        assertTrue("Message should have arrived", success[0]);
    }

    private void cleanUpStore() {
        FileBasedOmemoStoreV2.deleteRecursively(storePath);
    }

    private void cleanUpPubSub(OmemoManager omemoManager) {
        PubSubManager pm = PubSubManager.getInstance(omemoManager.getConnection(),omemoManager.getOwnJid());
        try {
            pm.deleteNode(OmemoConstants.PEP_NODE_BUNDLE_FROM_DEVICE_ID(omemoManager.getDeviceId()));
            pm.deleteNode(OmemoConstants.PEP_NODE_DEVICE_LIST);
        } catch (SmackException.NoResponseException | InterruptedException | SmackException.NotConnectedException | XMPPException.XMPPErrorException e) {
            LOGGER.log(Level.WARNING, "Exception while deleting used OMEMO PubSub node: "+e.getMessage());
        }
    }
}
