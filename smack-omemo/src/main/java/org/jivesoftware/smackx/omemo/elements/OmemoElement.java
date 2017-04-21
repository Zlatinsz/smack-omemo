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

/**
 * Class that represents a OmemoElement.
 * TODO: Move functionality here.
 *
 * @author Paul Schaub
 */
public abstract class OmemoElement implements ExtensionElement {

    public static final String ENCRYPTED = "encrypted";
    public static final String HEADER = "header";
    public static final String SID = "sid";
    public static final String KEY = "key";
    public static final String RID = "rid";
    public static final String PREKEY = "prekey";
    public static final String IV = "iv";
    public static final String PAYLOAD = "payload";
}
