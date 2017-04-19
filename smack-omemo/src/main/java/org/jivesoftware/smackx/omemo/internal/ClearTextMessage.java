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
package org.jivesoftware.smackx.omemo.internal;

import org.jivesoftware.smack.packet.Message;

/**
 * Class that bundles a decrypted message together with the original message and some information about the encryption.
 *
 * @author Paul Schaub
 * @param <T_IdKey>    Type of the IdentityKey.
 */
public class ClearTextMessage<T_IdKey> {
    private final String body;
    private final Message encryptedMessage;
    private final OmemoMessageInformation<T_IdKey> messageInformation;

    public ClearTextMessage(String message, Message original, OmemoMessageInformation<T_IdKey> messageInfo) {
        this.body = message;
        this.encryptedMessage = original;
        this.messageInformation = messageInfo;
    }

    /**
     * Return the body of the decrypted message.
     *
     * @return plaintext body
     */
    public String getBody() {
        return body;
    }

    /**
     * Return the original Message object.
     *
     * @return original message
     */
    public Message getOriginalMessage() {
        return encryptedMessage;
    }

    /**
     * Return the OmemoMessageInformation.
     *
     * @return omemoMessageInformation
     */
    public OmemoMessageInformation<T_IdKey> getMessageInformation() {
        return messageInformation;
    }
}
