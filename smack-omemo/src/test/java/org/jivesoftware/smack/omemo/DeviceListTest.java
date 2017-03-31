package org.jivesoftware.smack.omemo;

import org.jivesoftware.smackx.omemo.elements.OmemoDeviceListElement;
import org.jivesoftware.smackx.omemo.internal.CachedDeviceList;
import org.junit.Test;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;


/**
 * Test behavior of device lists
 *
 * @author Paul Schaub
 */
public class DeviceListTest {


    /**
     * Test, whether deviceList updates are correctly merged into the cached device list.
     * IDs in the update become active devices, active IDs that were not in the update become inactive.
     * Inactive IDs that were not in the update stay inactive.
     */
    @Test
    public void mergeDeviceListsTest() {
        CachedDeviceList cached = new CachedDeviceList();
        assertNotNull(cached.getActiveDevices());
        assertNotNull(cached.getInactiveDevices());

        cached.getInactiveDevices().add(1);
        cached.getInactiveDevices().add(2);
        cached.getActiveDevices().add(3);

        OmemoDeviceListElement update = new OmemoDeviceListElement();
        update.add(4);
        update.add(1);

        cached.merge(update);

        assertTrue(cached.getActiveDevices().contains(1) &&
                !cached.getActiveDevices().contains(2) &&
                !cached.getActiveDevices().contains(3) &&
                cached.getActiveDevices().contains(4));

        assertTrue(!cached.getInactiveDevices().contains(1) &&
                cached.getInactiveDevices().contains(2) &&
                cached.getInactiveDevices().contains(3) &&
                !cached.getInactiveDevices().contains(4));

        assertTrue(cached.getAllDevices().size() == 4);
    }
}
