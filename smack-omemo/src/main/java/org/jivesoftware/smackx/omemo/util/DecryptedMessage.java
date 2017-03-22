package org.jivesoftware.smackx.omemo.util;

import org.jivesoftware.smack.packet.Message;
import org.jivesoftware.smackx.omemo.internal.OmemoMessageInformation;

/**
 * Created by Paul Schaub on 22.03.17.
 */
public class DecryptedMessage<T_IdKey> {
    private String body;
    private Message encryptedMessage;
    private OmemoMessageInformation<T_IdKey> messageInformation;

    public DecryptedMessage(String message, Message original, OmemoMessageInformation<T_IdKey> messageInfo) {
        this.body = message;
        this.encryptedMessage = original;
        this.messageInformation = messageInfo;
    }

    public String getBody() {
        return body;
    }

    public Message getEncryptedMessage() {
        return encryptedMessage;
    }

    public OmemoMessageInformation<T_IdKey> getMessageInformation() {
        return messageInformation;
    }
}
