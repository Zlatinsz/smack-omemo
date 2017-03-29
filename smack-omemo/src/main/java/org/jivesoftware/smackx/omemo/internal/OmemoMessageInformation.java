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
package org.jivesoftware.smackx.omemo.internal;

/**
 * Class that contains information about a decrypted message (eg. which key was used, if it was a carbon...).
 *
 * @param <T_IdKey> IdentityKey class
 * @author Paul Schaub
 */
public class OmemoMessageInformation<T_IdKey> {
    private boolean isOmemoMessage;
    private T_IdKey senderIdentityKey;
    private OmemoDevice senderDevice;
    private CARBON carbon = CARBON.NONE;

    /**
     * Empty constructor.
     */
    public OmemoMessageInformation() {
    }

    /**
     * Creates a new OmemoMessageInformation object.
     *
     * @param senderIdentityKey identityKey of the sender device
     * @param senderDevice      device that sent the message
     * @param carbon            Carbon type
     */
    public OmemoMessageInformation(T_IdKey senderIdentityKey, OmemoDevice senderDevice, CARBON carbon) {
        this.senderIdentityKey = senderIdentityKey;
        this.senderDevice = senderDevice;
        this.carbon = carbon;
        this.isOmemoMessage = true;
    }

    public OmemoMessageInformation(T_IdKey senderIdentityKey, OmemoDevice senderDevice, CARBON carbon, boolean omemo) {
        this(senderIdentityKey, senderDevice, carbon);
        this.isOmemoMessage = omemo;
    }

    /**
     * Return the sender devices identityKey.
     *
     * @return identityKey
     */
    public T_IdKey getSenderIdentityKey() {
        return senderIdentityKey;
    }

    /**
     * Set the sender devices identityKey.
     *
     * @param senderIdentityKey identityKey
     */
    public void setSenderIdentityKey(T_IdKey senderIdentityKey) {
        this.senderIdentityKey = senderIdentityKey;
    }

    /**
     * Return the sender device.
     *
     * @return sender device
     */
    public OmemoDevice getSenderDevice() {
        return senderDevice;
    }

    /**
     * Return true, if this is (was) an OMEMO message.
     * @return true if omemo
     */
    public boolean isOmemoMessage() {
        return this.isOmemoMessage;
    }

    /**
     * Set the sender device.
     *
     * @param senderDevice sender device
     */
    public void setSenderDevice(OmemoDevice senderDevice) {
        this.senderDevice = senderDevice;
    }

    /**
     * Return the carbon type.
     *
     * @return carbon type
     */
    public CARBON getCarbon() {
        return carbon;
    }

    /**
     * Set the carbon type.
     *
     * @param carbon carbon type
     */
    public void setCarbon(CARBON carbon) {
        this.carbon = carbon;
    }

    /**
     * Types of Carbon Messages.
     */
    public enum CARBON {
        NONE,   //No carbon
        SENT,   //Sent carbon
        RECV    //Received Carbon
    }

    @Override
    public String toString() {
        return (senderDevice != null ? senderDevice.toString() : "") + " " + carbon;
    }
}


