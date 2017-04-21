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

import java.util.HashSet;

/**
 * Class that represents a OmemoDeviceList.
 * TODO: Move functionality to here.
 *
 * @author Paul Schaub
 */
public abstract class OmemoDeviceListElement extends HashSet<Integer> implements ExtensionElement {

    private static final long serialVersionUID = 635212332059449259L;

    public static final String DEVICE = "device";
    public static final String ID = "id";
    public static final String LIST = "list";

}
