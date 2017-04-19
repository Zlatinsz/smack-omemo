/**
 *
 * Copyright the original author or authors
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

import org.jivesoftware.smack.SmackException;
import org.jivesoftware.smack.XMPPException;
import org.jivesoftware.smackx.omemo.OmemoManager;
import org.jivesoftware.smackx.omemo.elements.OmemoBundleElement;
import org.jivesoftware.smackx.omemo.elements.OmemoDeviceListElement;
import org.jivesoftware.smackx.omemo.internal.OmemoDevice;
import org.jivesoftware.smackx.pubsub.LeafNode;
import org.jivesoftware.smackx.pubsub.PayloadItem;
import org.jivesoftware.smackx.pubsub.PubSubException;
import org.jivesoftware.smackx.pubsub.PubSubManager;
import org.jxmpp.jid.BareJid;

import static org.jivesoftware.smackx.omemo.util.OmemoConstants.PEP_NODE_BUNDLE_FROM_DEVICE_ID;
import static org.jivesoftware.smackx.omemo.util.OmemoConstants.PEP_NODE_DEVICE_LIST;

/**
 * Really dirty Workaround for the PubSub Node problem...
 *
 * @author Paul Schaub
 */
public class PubSubHelper {

    // TODO This class should simply be part of OmemoService -Flow
    private final OmemoManager manager;

    public PubSubHelper(OmemoManager manager) {
        this.manager = manager;
    }

    /**
     * Fetch our own device list node.
     *
     * @return leafNode
     * @throws InterruptedException
     * @throws PubSubException.NotALeafNodeException
     * @throws XMPPException.XMPPErrorException
     * @throws SmackException.NotConnectedException
     * @throws SmackException.NoResponseException
     */
    public LeafNode fetchDeviceListNode() throws InterruptedException, PubSubException.NotALeafNodeException,
            XMPPException.XMPPErrorException, SmackException.NotConnectedException, SmackException.NoResponseException {
        return PubSubManager.getInstance(manager.getConnection(),
                manager.getConnection().getUser().asBareJid()).getLeafNode(PEP_NODE_DEVICE_LIST);
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
    public LeafNode fetchDeviceListNode(BareJid contact)
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
    public OmemoDeviceListElement fetchDeviceList(BareJid contact) throws XMPPException.XMPPErrorException, SmackException.NotConnectedException, InterruptedException, SmackException.NoResponseException, PubSubException.NotALeafNodeException {
        return extractDeviceListFrom(fetchDeviceListNode(contact));
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
    public OmemoBundleElement fetchBundle(OmemoDevice contact) throws XMPPException.XMPPErrorException, SmackException.NotConnectedException, InterruptedException, SmackException.NoResponseException, PubSubException.NotALeafNodeException {
        LeafNode node = PubSubManager.getInstance(manager.getConnection(), contact.getJid()).getLeafNode(PEP_NODE_BUNDLE_FROM_DEVICE_ID(contact.getDeviceId()));
        if (node != null) {
            return extractBundleFrom(node);
        } else {
            return null;
        }
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
    public OmemoBundleElement extractBundleFrom(LeafNode node) throws XMPPException.XMPPErrorException, SmackException.NotConnectedException, InterruptedException, SmackException.NoResponseException {
        if (node == null) {
            return null;
        }
        try {
            return (OmemoBundleElement) ((PayloadItem<?>) node.getItems().get(0)).getPayload();
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
    public OmemoDeviceListElement extractDeviceListFrom(LeafNode node) throws XMPPException.XMPPErrorException, SmackException.NotConnectedException, InterruptedException, SmackException.NoResponseException {
        if (node == null) {
            return null;
        }
        if(node.getItems().size() > 0) {
            OmemoDeviceListElement listElement = (OmemoDeviceListElement) ((PayloadItem<?>) node.getItems().get(node.getItems().size() - 1)).getPayload();
            if(node.getItems().size() > 1) {
                node.deleteAllItems();
                node.send(new PayloadItem<>(listElement));
            }
            return listElement;
        }
        return new OmemoDeviceListElement();
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
    public void publishDeviceIds(OmemoDeviceListElement deviceList)
            throws InterruptedException, XMPPException.XMPPErrorException,
            SmackException.NotConnectedException, SmackException.NoResponseException, PubSubException.NotALeafNodeException {
        PubSubManager.getInstance(manager.getConnection(), manager.getConnection().getUser().asBareJid())
                .tryToPublishAndPossibleAutoCreate(OmemoConstants.PEP_NODE_DEVICE_LIST, new PayloadItem<>(deviceList));
    }

    /**
     * Publish the given OMEMO bundle to the server.
     *
     * @param bundleElement OMEMO bundle
     * @param deviceId      DeviceId of the bundles device
     * @throws XMPPException.XMPPErrorException
     * @throws SmackException.NotConnectedException
     * @throws InterruptedException
     * @throws SmackException.NoResponseException
     */
    public void publishOmemoBundle(OmemoBundleElement bundleElement, int deviceId)
            throws XMPPException.XMPPErrorException, SmackException.NotConnectedException, InterruptedException,
            SmackException.NoResponseException {
        PubSubManager.getInstance(manager.getConnection(), manager.getConnection().getUser().asBareJid())
                .tryToPublishAndPossibleAutoCreate(OmemoConstants.PEP_NODE_BUNDLE_FROM_DEVICE_ID(deviceId),
                        new PayloadItem<>(bundleElement));
    }
}
