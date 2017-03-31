package org.jivesoftware.smack.omemo;

import org.jivesoftware.smackx.omemo.internal.OmemoDevice;
import org.junit.Assert;
import org.junit.Test;
import org.jxmpp.jid.BareJid;
import org.jxmpp.jid.impl.JidCreate;
import org.jxmpp.stringprep.XmppStringprepException;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 * Test the OmemoDevice class
 *
 * @author Paul Schaub
 */
public class OmemoDeviceTest {

    /**
     * Test, if the equals() method works as intended.
     */
    @Test
    public void testEquals() {
        BareJid romeo, juliet, guyUnderTheBalcony;
        try {
            romeo = JidCreate.bareFrom("romeo@shakespeare.lit");
            guyUnderTheBalcony = JidCreate.bareFrom("romeo@shakespeare.lit/underTheBalcony");
            juliet = JidCreate.bareFrom("juliet@shakespeare.lit");
        } catch (XmppStringprepException e) {
            Assert.fail(e.getMessage());
            return;
        }

        OmemoDevice r = new OmemoDevice(romeo, 1);
        OmemoDevice g = new OmemoDevice(guyUnderTheBalcony, 1);
        OmemoDevice r2 = new OmemoDevice(romeo, 2);
        OmemoDevice j = new OmemoDevice(juliet, 3);
        OmemoDevice j2 = new OmemoDevice(juliet, 1);

        assertTrue(r.equals(g));
        assertFalse(r.equals(r2));
        assertFalse(j.equals(j2));
        assertFalse(j2.equals(r2));
    }
}
