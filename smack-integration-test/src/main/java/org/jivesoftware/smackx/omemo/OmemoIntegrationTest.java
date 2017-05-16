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

import junit.framework.TestCase;
import org.igniterealtime.smack.inttest.AbstractSmackIntegrationTest;
import org.igniterealtime.smack.inttest.SmackIntegrationTest;
import org.igniterealtime.smack.inttest.SmackIntegrationTestEnvironment;
import org.igniterealtime.smack.inttest.TestNotPossibleException;
import org.jivesoftware.smack.SmackException;
import org.jivesoftware.smack.XMPPException;
import org.jivesoftware.smack.chat2.ChatManager;
import org.jivesoftware.smack.packet.Message;
import org.jivesoftware.smack.roster.Roster;
import org.jivesoftware.smack.roster.RosterEntry;
import org.jivesoftware.smackx.omemo.elements.OmemoBundleElement;
import org.jivesoftware.smackx.omemo.elements.OmemoElement;
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
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.util.logging.Level;

import static junit.framework.TestCase.assertEquals;
import static junit.framework.TestCase.assertNotNull;
import static junit.framework.TestCase.assertNotSame;
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
    @SmackIntegrationTest
    public  void initializationTest() throws XMPPException.XMPPErrorException, PubSubException.NotALeafNodeException, SmackException.NotConnectedException, InterruptedException, SmackException.NoResponseException, SmackException.NotLoggedInException, CorruptedOmemoKeyException {
        OmemoManager omemoManager = OmemoManager.getInstanceFor(conThree, 666);
        OmemoStore<?,?,?,?,?,?,?,?,?> omemoStore = omemoManager.getOmemoService().getOmemoStoreBackend();
        omemoStore.purgeOwnDeviceKeys(omemoManager);

        //test keys.
        setUpOmemoManager(omemoManager);
        assertNotNull("IdentityKey must not be null after initialization.", omemoStore.loadOmemoIdentityKeyPair(omemoManager));
        assertTrue("We must have "+OmemoConstants.TARGET_PRE_KEY_COUNT+" preKeys.",
                omemoStore.loadOmemoPreKeys(omemoManager).size() == OmemoConstants.TARGET_PRE_KEY_COUNT);
        assertNotNull("Our signedPreKey must not be null.", omemoStore.loadCurrentSignedPreKeyId(omemoManager));

        //Is deviceId published?
        assertTrue("Published deviceList must contain our deviceId.",
                omemoManager.getOmemoService().fetchDeviceList(omemoManager, omemoManager.getOwnJid())
                .getDeviceIds().contains(omemoManager.getDeviceId()));

        //clean up
        clean(omemoManager);
    }

    /**
     * This Test tests sending and receiving messages.
     * Alice and Bob create fresh devices, then they add another to their rosters.
     * Next they build sessions with one another and Alice sends a message to Bob.
     * After receiving and successfully decrypting the message, its tested, if Bob
     * publishes a new Bundle. After that Bob replies to the message and its tested,
     * whether Alice can decrypt the message and if she does NOT publish a new Bundle.
     *
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
        final String alicesSecret = "Hey Bob! I love you!";
        final String bobsSecret = "I love you too, Alice."; //aww <3
        final boolean[] success = new boolean[2];
        final int maxTenthsSecondsWait = 600;
        int tenthsSecondsWaited = 0;

        cleanUpStore();

        //Get Managers and Stores
        OmemoManager alice = OmemoManager.getInstanceFor(conOne, aliceId);
        OmemoManager bob = OmemoManager.getInstanceFor(conTwo, bobsId);
        OmemoStore<?,?,?,?,?,?,?,?,?> omemoStore = OmemoService.getInstance().getOmemoStoreBackend();

        //initialize OmemoManagers
        setUpOmemoManager(alice);
        setUpOmemoManager(bob);

        //Save initial bundles
        OmemoBundleElement aliceBundle = omemoStore.packOmemoBundle(alice);
        OmemoBundleElement bobsBundle = omemoStore.packOmemoBundle(bob);

        //Subscribe to one another
        subscribe(alice, bob, "Bob");
        subscribe(bob, alice,"Alice");

        unidirectionalTrust(alice, bob);
        unidirectionalTrust(bob, alice);

        //Register messageListeners
        bob.addOmemoMessageListener(new OmemoMessageListener() {
            @Override
            public void onOmemoMessageReceived(String decryptedBody, Message encryptedMessage, Message wrappingMessage, OmemoMessageInformation omemoInformation) {
                LOGGER.log(Level.INFO,"Bob received message: "+decryptedBody);
                assertEquals(decryptedBody.trim(), alicesSecret.trim());
                success[0] = true;
            }

            @Override
            public void onOmemoKeyTransportReceived(CipherAndAuthTag cipherAndAuthTag, Message message, Message wrappingMessage, OmemoMessageInformation omemoInformation) {
            }
        });

        alice.addOmemoMessageListener(new OmemoMessageListener() {
            @Override
            public void onOmemoMessageReceived(String decryptedBody, Message encryptedMessage, Message wrappingMessage, OmemoMessageInformation omemoInformation) {
                LOGGER.log(Level.INFO, "Alice received message: "+decryptedBody);
                assertEquals(decryptedBody.trim(), bobsSecret.trim());
                success[1] = true;
            }

            @Override
            public void onOmemoKeyTransportReceived(CipherAndAuthTag cipherAndAuthTag, Message message, Message wrappingMessage, OmemoMessageInformation omemoInformation) {

            }
        });

        //Prepare Alice message for Bob
        Message messageA = new Message(bob.getOwnJid(), alicesSecret);
        Message encryptedA = alice.encrypt(bob.getOwnJid(), messageA);
        ChatManager.getInstanceFor(alice.getConnection()).chatWith(bob.getOwnJid().asEntityBareJidIfPossible())
                .send(encryptedA);

        //Wait for message
        while (!success[0] && tenthsSecondsWaited < maxTenthsSecondsWait) {
            tenthsSecondsWaited++;
            Thread.sleep(100);
        }

        if(!success[0]) {
            TestCase.fail("Bob must have received Alice message.");
        }

        //Check if Bob published a new Bundle
        assertNotSame("Bob must have published another bundle at this point, since we used a PreKeyMessage.",
                bobsBundle, OmemoService.getInstance().fetchBundle(alice, bob.getOwnDevice()));

        //Prepare Bobs response
        Message messageB = new Message(alice.getOwnJid(), bobsSecret);
        Message encryptedB = bob.encrypt(alice.getOwnJid(), messageB);
        ChatManager.getInstanceFor(bob.getConnection()).chatWith(alice.getOwnJid().asEntityBareJidIfPossible())
                .send(encryptedB);

        //Wait for response
        tenthsSecondsWaited = 0;
        while (!success[1] && tenthsSecondsWaited < maxTenthsSecondsWait) {
            tenthsSecondsWaited++;
            Thread.sleep(100);
        }

        if(!success[1]) {
            TestCase.fail("Alice must have received a response from Bob.");
        }

        assertEquals("Alice must not have published a new bundle, since we built the session using Bobs bundle.",
                aliceBundle, OmemoService.getInstance().fetchBundle(bob, alice.getOwnDevice()));

        //Clean up
        clean(alice);
        clean(bob);

        assertTrue("Message should have arrived", success[0]);
    }

    public void keyTransportMessageTest() throws CorruptedOmemoKeyException, InterruptedException, SmackException.NoResponseException, SmackException.NotConnectedException, XMPPException.XMPPErrorException, SmackException.NotLoggedInException, PubSubException.NotALeafNodeException, CannotEstablishOmemoSessionException, CryptoFailedException, UndecidedOmemoIdentityException {
        final boolean[] success = new boolean[1];
        final int maxTenthsSecondsWait = 600;
        int tenthSecondsWaited = 0;
        OmemoManager alice = OmemoManager.getInstanceFor(conOne, 555);
        OmemoManager bob = OmemoManager.getInstanceFor(conTwo, 333);

        setUpOmemoManager(alice);
        setUpOmemoManager(bob);

        subscribe(alice, bob, "Bob");
        unidirectionalTrust(alice, bob);

        final byte[] key = new byte[16];
        final byte[] iv = new byte[16];
        INSECURE_RANDOM.nextBytes(key);
        INSECURE_RANDOM.nextBytes(iv);

        bob.addOmemoMessageListener(new OmemoMessageListener() {
            @Override
            public void onOmemoMessageReceived(String decryptedBody, Message encryptedMessage, Message wrappingMessage, OmemoMessageInformation omemoInformation) {

            }

            @Override
            public void onOmemoKeyTransportReceived(CipherAndAuthTag cipherAndAuthTag, Message message, Message wrappingMessage, OmemoMessageInformation omemoInformation) {
                try {
                    assertEquals(cipherAndAuthTag.getCipher().getParameters().getEncoded(), key);
                    assertEquals(cipherAndAuthTag.getCipher().getIV(), iv);
                    success[0] = true;
                } catch (IOException e) {
                    TestCase.fail("Key should be retrievable from cipher.");
                }
            }
        });

        OmemoElement keyTransportMessage = alice.createKeyTransportElement(key, iv, bob.getOwnDevice());
        Message m = new Message(bob.getOwnJid());
        m.addExtension(keyTransportMessage);
        ChatManager.getInstanceFor(alice.getConnection()).chatWith(bob.getOwnJid().asEntityBareJidIfPossible()).send(m);

        while (!success[0] && tenthSecondsWaited < maxTenthsSecondsWait) {
            Thread.sleep(100);
            tenthSecondsWaited++;
        }

        if(!success[0]) {
            TestCase.fail("Bob must have received the keyTransportMessage.");
        }

        clean(alice);
        clean(bob);
    }

    private void clean(OmemoManager omemoManager) throws SmackException.NotLoggedInException, XMPPException.XMPPErrorException, SmackException.NotConnectedException, InterruptedException, SmackException.NoResponseException {
        cleanUpPubSub(omemoManager);
        cleanUpRoster(omemoManager);
        cleanUpStore(omemoManager);
    }

    private void cleanUpStore() {
        FileBasedOmemoStoreV2.deleteRecursively(storePath);
    }

    private void cleanUpStore(OmemoManager omemoManager) {
        OmemoService.getInstance().getOmemoStoreBackend().purgeOwnDeviceKeys(omemoManager);
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

    private void cleanUpRoster(OmemoManager omemoManager) {
        Roster roster = Roster.getInstanceFor(omemoManager.getConnection());
        for(RosterEntry r : roster.getEntries()) {
            try {
                roster.removeEntry(r);
            } catch (InterruptedException | SmackException.NoResponseException | SmackException.NotConnectedException | XMPPException.XMPPErrorException | SmackException.NotLoggedInException e) {
                LOGGER.log(Level.WARNING, "Exception while deleting roster enrty: "+e.getMessage());
            }
        }
    }

    /**
     * Let Alice subscribe to Bob.
     * @param alice
     * @param bob
     * @throws SmackException.NotLoggedInException
     * @throws XMPPException.XMPPErrorException
     * @throws SmackException.NotConnectedException
     * @throws InterruptedException
     * @throws SmackException.NoResponseException
     */
    private void subscribe(OmemoManager alice, OmemoManager bob, String nick)
            throws SmackException.NotLoggedInException, XMPPException.XMPPErrorException,
            SmackException.NotConnectedException, InterruptedException,
            SmackException.NoResponseException {

        Roster aliceRoster = Roster.getInstanceFor(alice.getConnection());
        Roster bobsRoster = Roster.getInstanceFor(bob.getConnection());
        bobsRoster.setSubscriptionMode(Roster.SubscriptionMode.accept_all);
        aliceRoster.createEntry(bob.getOwnJid(), nick, null);
    }


    private void unidirectionalTrust(OmemoManager alice, OmemoManager bob) throws SmackException.NotConnectedException, InterruptedException, SmackException.NoResponseException, CannotEstablishOmemoSessionException {
        //Fetch deviceList
        alice.requestDeviceListUpdateFor(bob.getOwnJid());
        assertTrue("Trusting party must know the others device at this point.",
                alice.getOmemoService().getOmemoStoreBackend().loadCachedDeviceList(alice, bob.getOwnJid())
                        .getActiveDevices().contains(bob.getDeviceId()));

        //Create sessions
        alice.buildSessionsWith(bob.getOwnJid());
        assertTrue("Trusting party must have a session with the other end at this point.",
                !alice.getOmemoService().getOmemoStoreBackend().loadAllRawSessionsOf(alice, bob.getOwnJid()).isEmpty());

        //Trust the other party
        alice.getOmemoService().getOmemoStoreBackend().trustOmemoIdentity(alice, bob.getOwnDevice(),
                alice.getOmemoService().getOmemoStoreBackend().getFingerprint(alice, bob.getOwnDevice()));

    }

    private void setUpOmemoManager(OmemoManager omemoManager) throws CorruptedOmemoKeyException, InterruptedException, SmackException.NoResponseException, SmackException.NotConnectedException, XMPPException.XMPPErrorException, SmackException.NotLoggedInException, PubSubException.NotALeafNodeException {
        omemoManager.initialize();
        OmemoBundleElement bundle = OmemoService.getInstance().fetchBundle(omemoManager, omemoManager.getOwnDevice());
        assertNotNull("Bundle must not be null.", bundle);
        assertEquals("Published Bundle must equal our local bundle.", bundle, omemoManager.getOmemoService().getOmemoStoreBackend().packOmemoBundle(omemoManager));
    }
}
