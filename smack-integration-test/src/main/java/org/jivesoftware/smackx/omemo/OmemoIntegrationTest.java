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
import org.jivesoftware.smackx.omemo.exceptions.CorruptedOmemoKeyException;
import org.jivesoftware.smackx.pubsub.PubSubException;
import org.jxmpp.jid.BareJid;

import java.io.File;
import java.util.logging.Level;

import static junit.framework.TestCase.assertNotNull;
import static junit.framework.TestCase.assertNull;

public class OmemoIntegrationTest extends AbstractSmackIntegrationTest {

    private static File storePath = new File("int_test_omemo_store");
    private static int aliceId = 123456789;
    private static int bobId = 987654321;

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
     * Test if keys are generated properly.
     */
    @SmackIntegrationTest
    public void keyMaterialGenerationTest() {
        BareJid alice = conOne.getUser().asBareJid();
        OmemoManager omemoManager = OmemoManager.getInstanceFor(conOne, aliceId);
        OmemoStore<?,?,?,?,?,?,?,?,?> omemoStore = omemoManager.getOmemoService().getOmemoStoreBackend();

        try {
            assertNull("IdentityKey must be null before initialization.", omemoStore.loadOmemoIdentityKeyPair(omemoManager));
        } catch (CorruptedOmemoKeyException e) {
            LOGGER.log(Level.SEVERE, "Error in test: "+e.getMessage());
        }

        try {
            omemoManager.initialize();
            assertNotNull("IdentityKey must not be null after initialization.", omemoStore.loadOmemoIdentityKeyPair(omemoManager));
        } catch (CorruptedOmemoKeyException | PubSubException.NotALeafNodeException | SmackException.NotLoggedInException | XMPPException.XMPPErrorException | SmackException.NotConnectedException | SmackException.NoResponseException | InterruptedException e) {
            LOGGER.log(Level.SEVERE, "Error in test: "+e.getMessage());
        }
    }

    public void cleanUpStore() {
        FileBasedOmemoStoreV2.deleteRecursively(storePath);
    }
}
