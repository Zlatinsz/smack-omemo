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
package org.jivesoftware.smackx.omemo.provider;

import org.jivesoftware.smack.provider.ExtensionElementProvider;
import org.jivesoftware.smackx.omemo.elements.OmemoDeviceListVAxolotlElement;
import org.xmlpull.v1.XmlPullParser;

import static org.jivesoftware.smackx.omemo.elements.OmemoDeviceListElement.DEVICE;
import static org.jivesoftware.smackx.omemo.elements.OmemoDeviceListElement.ID;
import static org.jivesoftware.smackx.omemo.elements.OmemoDeviceListElement.LIST;
import static org.xmlpull.v1.XmlPullParser.END_TAG;
import static org.xmlpull.v1.XmlPullParser.START_TAG;

/**
 * Smack ExtensionProvider that parses OMEMO device list elements into OmemoDeviceListElement objects.
 *
 * @author Paul Schaub
 */
public class OmemoDeviceListVAxolotlProvider extends ExtensionElementProvider<OmemoDeviceListVAxolotlElement> {

    @Override
    public OmemoDeviceListVAxolotlElement parse(XmlPullParser parser, int initialDepth) throws Exception {
        OmemoDeviceListVAxolotlElement list = new OmemoDeviceListVAxolotlElement();
        boolean stop = false;
        while (!stop) {
            int tag = parser.next();
            String name = parser.getName();
            switch (tag) {
                case START_TAG:
                    if (name.equals(DEVICE)) {
                        for (int i = 0; i < parser.getAttributeCount(); i++) {
                            if (parser.getAttributeName(i).equals(ID)) {
                                list.add(Integer.parseInt(parser.getAttributeValue(i)));
                            }
                        }
                    }
                    break;
                case END_TAG:
                    if (name.equals(LIST)) {
                        stop = true;
                    }
                    break;
            }
        }
        return list;
    }
}
