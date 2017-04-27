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
package org.jivesoftware.smackx.omemo.elements;

import org.jivesoftware.smack.packet.ExtensionElement;
import org.jivesoftware.smack.util.Objects;

import java.util.ArrayList;

/**
 * Class that represents a OmemoElement.
 * TODO: Move functionality here.
 *
 * @author Paul Schaub
 */
public abstract class OmemoElement implements ExtensionElement {

    public static final int TYPE_OMEMO_PREKEY_MESSAGE = 1;
    public static final int TYPE_OMEMO_MESSAGE = 0;

    public static final String ENCRYPTED = "encrypted";
    public static final String HEADER = "header";
    public static final String SID = "sid";
    public static final String KEY = "key";
    public static final String RID = "rid";
    public static final String PREKEY = "prekey";
    public static final String IV = "iv";
    public static final String PAYLOAD = "payload";

    protected final OmemoElement.OmemoHeader header;
    protected final byte[] payload;

    /**
     * Create a new OmemoMessageElement from a header and a payload.
     *
     * @param header  header of the message
     * @param payload payload
     */
    public OmemoElement(OmemoElement.OmemoHeader header, byte[] payload) {
        this.header = Objects.requireNonNull(header);
        this.payload = payload;
    }

    public OmemoElement.OmemoHeader getHeader() {
        return header;
    }

    /**
     * Return the payload of the message.
     *
     * @return payload
     */
    public byte[] getPayload() {
        if (payload == null) {
            return null;
        }
        return payload.clone();
    }

    public boolean isKeyTransportElement() {
        return payload == null;
    }

    public boolean isMessageElement() {
        return payload != null;
    }

    /**
     * Header element of the message. The header contains information about the sender and the encrypted keys for
     * the recipients, as well as the iv element for AES.
     */
    public static class OmemoHeader {
        private final int sid;
        private final ArrayList<Key> keys;
        private final byte[] iv;

        public OmemoHeader(int sid, ArrayList<OmemoHeader.Key> keys, byte[] iv) {
            this.sid = sid;
            this.keys = keys;
            this.iv = iv;
        }

        /**
         * Return the deviceId of the sender of the message.
         *
         * @return senders id
         */
        public int getSid() {
            return sid;
        }

        public ArrayList<OmemoHeader.Key> getKeys() {
            ArrayList<OmemoHeader.Key> copy = new ArrayList<>();
            for (OmemoHeader.Key k : keys) {
                copy.add(new OmemoHeader.Key(k.getData(), k.getId()));
            }
            return copy;
        }

        public byte[] getIv() {
            return iv != null ? iv.clone() : null;
        }

        /**
         * Small class to collect key (byte[]), its id and whether its a prekey or not.
         */
        public static class Key {
            final byte[] data;
            final int id;
            final boolean preKey;

            public Key(byte[] data, int id) {
                this.data = data;
                this.id = id;
                this.preKey = false;
            }

            public Key(byte[] data, int id, boolean preKey) {
                this.data = data;
                this.id = id;
                this.preKey = preKey;
            }

            public int getId() {
                return this.id;
            }

            public byte[] getData() {
                return this.data;
            }

            public boolean isPreKey() {
                return this.preKey;
            }
        }
    }
}
