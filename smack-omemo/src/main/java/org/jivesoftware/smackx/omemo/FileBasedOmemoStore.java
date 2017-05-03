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
package org.jivesoftware.smackx.omemo;

import org.jivesoftware.smack.util.StringUtils;
import org.jivesoftware.smackx.omemo.exceptions.CorruptedOmemoKeyException;
import org.jivesoftware.smackx.omemo.internal.CachedDeviceList;
import org.jivesoftware.smackx.omemo.internal.OmemoDevice;
import org.jxmpp.jid.BareJid;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Simple file based OmemoStore that stores values in a folder hierarchy.
 *
 * @param <T_IdKeyPair> IdentityKeyPair class
 * @param <T_IdKey>     IdentityKey class
 * @param <T_PreKey>    PreKey class
 * @param <T_SigPreKey> SignedPreKey class
 * @param <T_Sess>      Session class
 * @param <T_Addr>      Address class
 * @param <T_ECPub>     Elliptic Curve PublicKey class
 * @param <T_Bundle>    Bundle class
 * @param <T_Ciph>      Cipher class
 * @author Paul Schaub
 */
public abstract class FileBasedOmemoStore<T_IdKeyPair, T_IdKey, T_PreKey, T_SigPreKey, T_Sess, T_Addr, T_ECPub, T_Bundle, T_Ciph>
        extends OmemoStore<T_IdKeyPair, T_IdKey, T_PreKey, T_SigPreKey, T_Sess, T_Addr, T_ECPub, T_Bundle, T_Ciph> {
    private static final String LAST_PRE_KEY_ID = "lastPreKeyId";
    private static final String IDENTITY_KEY_PAIR = "identityKeyPair";
    private static final String IDENTITY_KEY = "identityKey";
    private static final String CURRENT_SIGNED_PRE_KEY = "currentSignedPreKey";
    private static final String SESSION = "session";
    private static final String TRUST = "trust";
    private static final String DEVICE_LIST = "deviceList";
    private static final String LAST_MESSAGE_RECEIVED = "lastMessageReceived";
    private static final String LAST_SIGNED_PREKEY_RENEWAL = "lastSignedPreKeyRenewal";

    private static final Logger LOGGER = Logger.getLogger(FileBasedOmemoStore.class.getName());

    private final File base;

    /**
     * Constructor.
     *
     * @param manager omemoManager
     * @param base    base path of the store
     */
    public FileBasedOmemoStore(OmemoManager manager, File base) {
        super(manager);
        if (!base.exists()) {
            base.mkdirs();
        }
        this.base = base;
    }

    @Override
    public boolean isFreshInstallation() {
        File userPath = getUserPath();
        return !new File(getUserPath() + "/" + omemoManager.getDeviceId()).exists();
    }

    @Override
    public int loadLastPreKeyId() {
        File dir = getDevicePath();
        if (dir == null) {
            return 0;
        }

        File[] l = dir.listFiles();
        if (l == null) {
            return 0;
        }

        for (File f : l) {
            if (f.getName().equals(LAST_PRE_KEY_ID)) {
                int i = readInt(f);
                if (i != -1) {
                    return i;
                }
            }
        }

        return 0;
    }

    @Override
    public void storeLastPreKeyId(int currentPreKeyId) {
        File dir = getDevicePath();
        if (dir != null) {
            writeInt(new File(dir.getAbsolutePath() + "/" + LAST_PRE_KEY_ID), currentPreKeyId);
        }
    }

    @Override
    public T_IdKeyPair loadOmemoIdentityKeyPair() throws CorruptedOmemoKeyException {
        File dir = getDevicePath();
        if(dir == null) {
            return null;
        }

        byte[] bytes = readBytes(new File(dir.getAbsolutePath() + "/" + IDENTITY_KEY_PAIR));
        return (bytes != null ? keyUtil().identityKeyPairFromBytes(bytes) : null);
    }

    @Override
    public void storeOmemoIdentityKeyPair(T_IdKeyPair identityKeyPair) {
        File dir = getDevicePath();
        if (dir != null) {
            writeBytes(keyUtil().identityKeyPairToBytes(identityKeyPair), new File(dir.getAbsolutePath() + "/" + IDENTITY_KEY_PAIR));
        }
    }

    @Override
    public T_IdKey loadOmemoIdentityKey(OmemoDevice device) throws CorruptedOmemoKeyException {
        File dir = getContactDevicePath(device);
        if (dir == null) {
            return null;
        }

        byte[] bytes = readBytes(new File(dir.getAbsolutePath() + "/" + IDENTITY_KEY));
        return (bytes != null ? keyUtil().identityKeyFromBytes(bytes) : null);
    }

    @Override
    public void storeOmemoIdentityKey(OmemoDevice device, T_IdKey identityKey) {
        File dir = getContactDevicePath(device);
        if (dir != null) {
            writeBytes(keyUtil().identityKeyToBytes(identityKey), new File(dir.getAbsolutePath() + "/" + IDENTITY_KEY));
        }
    }

    @Override
    public boolean isTrustedOmemoIdentity(OmemoDevice device, T_IdKey identityKey) {
        File dir = getContactDevicePath(device);
        if(dir == null) {
            return false;
        }

        File f = new File(dir.getAbsolutePath() + "/" + TRUST);
        byte[] bytes = readBytes(f);

        if(bytes == null) {
            return false;
        }

        if (bytes[0] != '1') {
            return false;
        }

        byte[] tfp = new byte[bytes.length - 1];
        System.arraycopy(bytes, 1, tfp, 0, tfp.length);

        byte[] fp;
        try {
            fp = keyUtil().getFingerprint(identityKey).getBytes(StringUtils.UTF8);
        } catch (UnsupportedEncodingException e) {
            LOGGER.log(Level.SEVERE, "isTrustedOmemoIdentity has failed due to an unsupported encoding: "
                    +e.getMessage());
            return false;
        }

        return Arrays.equals(fp, tfp);
    }

    @Override
    public boolean isDecidedOmemoIdentity(OmemoDevice device, T_IdKey identityKey) {
        File dir = getContactDevicePath(device);
        if (dir == null) {
            return false;
        }

        File f = new File(dir.getAbsolutePath() + "/" + TRUST);
        if (!f.exists() || !f.isFile()) {
            return false;
        }

        byte[] bytes = readBytes(f);
        if(bytes == null || bytes.length == 0) {
            return false;
        }

        byte[] tfp = new byte[bytes.length - 1];
        System.arraycopy(bytes, 1, tfp, 0, tfp.length);
        byte[] fp;

        try {
            fp = keyUtil().getFingerprint(identityKey).getBytes(StringUtils.UTF8);
        } catch (UnsupportedEncodingException e) {
            LOGGER.log(Level.SEVERE, "isDecidedOmemoIdentity has failed due to an unsupported encoding: "
                    +e.getMessage());
            return false;
        }

        return Arrays.equals(fp, tfp);
    }

    @Override
    public void trustOmemoIdentity(OmemoDevice device, T_IdKey identityKey) {
        File dir = getContactDevicePath(device);
        if(dir == null) {
            return;
        }

        File f = new File(dir.getAbsolutePath() + "/" + TRUST);
        byte[] a;

        try {
            a = keyUtil().getFingerprint(identityKey).getBytes(StringUtils.UTF8);
        } catch (UnsupportedEncodingException e) {
            LOGGER.log(Level.SEVERE, "trustOmemoIdentity failed due to unsupported encoding:"+e.getMessage());
            return;
        }
        //Prepend 1 to fingerpint to symbolize trust
        byte[] b = new byte[a.length + 1];
        b[0] = '1';
        System.arraycopy(a, 0, b, 1, a.length);
        writeBytes(b, f);
    }

    @Override
    public void distrustOmemoIdentity(OmemoDevice device, T_IdKey identityKey) {
        File dir = getContactDevicePath(device);
        if (dir == null) {
            return;
        }

        File f = new File(dir.getAbsolutePath() + "/" + TRUST);
        byte[] a;

        try {
            a = keyUtil().getFingerprint(identityKey).getBytes(StringUtils.UTF8);
        } catch (UnsupportedEncodingException e) {
            LOGGER.log(Level.SEVERE, "distrustOmemoIdentity failed due to unsupported encoding: "+e.getMessage());
            return;
        }
        //Prepend 0 to fingerprint to symbolize distrust
        byte[] b = new byte[a.length + 1];
        b[0] = '0';
        System.arraycopy(a, 0, b, 1, a.length);
        writeBytes(b, f);
    }

    @Override
    public T_PreKey loadOmemoPreKey(int preKeyId) {
        File dir = getPreKeysPath();
        if(dir == null) {
            return null;
        }

        File[] keys = dir.listFiles();
        if (keys == null) {
            return null;
        }

        for (File f : keys) {
            if (!f.getName().equals(Integer.toString(preKeyId))) {
                continue;
            }

            byte[] bytes = readBytes(f);
            if (bytes == null) {
                continue;
            }

            try {
                return keyUtil().preKeyFromBytes(bytes);
            } catch (IOException e) {
                LOGGER.log(Level.SEVERE, "loadOmemoPreKey has failed for file "
                        +f.getAbsolutePath()+": "+e.getMessage());
                return null;
            }
        }
        return null;
    }

    @Override
    public void storeOmemoPreKey(int preKeyId, T_PreKey preKeyRecord) {
        File dir = getPreKeysPath();
        if (dir != null) {
            File f = new File(dir.getAbsolutePath() + "/" + preKeyId);
            writeBytes(keyUtil().preKeyToBytes(preKeyRecord), f);
        }
    }

    @Override
    public void removeOmemoPreKey(int preKeyId) {
        File dir = getDevicePath();
        if (dir != null) {
            File f = new File(dir.getAbsolutePath() + "/" + preKeyId);
            f.delete();
        }
    }

    @Override
    public int loadCurrentSignedPreKeyId() {
        File dir = getDevicePath();
        if (dir == null) {
            return 0;
        }

        File f = new File(dir.getAbsolutePath() + "/" + CURRENT_SIGNED_PRE_KEY);
        int i = readInt(f);

        return (i != -1 ? i : 0);
    }

    @Override
    public void storeCurrentSignedPreKeyId(int currentSignedPreKeyId) {
        File dir = getDevicePath();
        if (dir != null) {
            File f = new File(dir.getAbsolutePath() + "/" + CURRENT_SIGNED_PRE_KEY);
            writeInt(f, currentSignedPreKeyId);
        }
    }

    @Override
    public HashMap<Integer, T_PreKey> loadOmemoPreKeys() {
        File dir = getPreKeysPath();
        HashMap<Integer, T_PreKey> preKeys = new HashMap<>();

        if (dir == null) {
            return preKeys;
        }

        File[] list = dir.listFiles();
        if (list == null) {
            return preKeys;
        }

        for (File f : list) {
            T_PreKey preKey;

            try {
                byte[] bytes = readBytes(f);

                if (bytes == null) {
                    continue;
                }

                preKey = keyUtil().preKeyFromBytes(bytes);
                preKeys.put(Integer.parseInt(f.getName()), preKey);
            } catch (IOException e) {
                LOGGER.log(Level.SEVERE, "loadOmemoPreKeys has failed for file "
                        +f.getAbsolutePath()+": "+e.getMessage());
            }
        }
        return preKeys;
    }

    @Override
    public T_SigPreKey loadOmemoSignedPreKey(int signedPreKeyId) {
        File dir = getSignedPreKeysPath();
        if (dir == null) {
            return null;
        }

        File f = new File(dir.getAbsolutePath() + "/" + signedPreKeyId);
        byte[] bytes = readBytes(f);

        if (bytes == null) {
            return null;
        }

        try {
            return keyUtil().signedPreKeyFromBytes(bytes);
        } catch (IOException e) {
            LOGGER.log(Level.SEVERE, "loadOmemoSignedPreKey has failed: "+e.getMessage());
            return null;
        }
    }

    @Override
    public HashMap<Integer, T_SigPreKey> loadOmemoSignedPreKeys() {
        File dir = getSignedPreKeysPath();
        HashMap<Integer, T_SigPreKey> signedPreKeys = new HashMap<>();

        if (dir == null) {
            return signedPreKeys;
        }

        File[] list = dir.listFiles();
        if (list == null) {
            return signedPreKeys;
        }

        for (File f : list) {
            byte[] bytes = readBytes(f);

            if(bytes == null) {
                continue;
            }

            try {
                T_SigPreKey s = keyUtil().signedPreKeyFromBytes(bytes);
                signedPreKeys.put(Integer.parseInt(f.getName()), s);
            } catch (IOException e) {
                LOGGER.log(Level.SEVERE, "loadOmemoSignedPreKeys has failed for file "
                        +f.getAbsolutePath()+": "+e.getMessage());
            }
        }
        return signedPreKeys;
    }

    @Override
    public void storeOmemoSignedPreKey(int signedPreKeyId, T_SigPreKey signedPreKey) {
        File dir = getSignedPreKeysPath();
        if (dir != null) {
            File f = new File(dir.getAbsolutePath() + "/" + signedPreKeyId);
            writeBytes(keyUtil().signedPreKeyToBytes(signedPreKey), f);
        }
    }

    @Override
    public void removeOmemoSignedPreKey(int signedPreKeyId) {
        File dir = getSignedPreKeysPath();
        if (dir != null) {
            File f = new File(dir.getAbsolutePath() + "/" + signedPreKeyId);
            f.delete();
        }
    }

    @Override
    public T_Sess loadRawSession(OmemoDevice device) {
        File dir = getContactDevicePath(device);
        if (dir == null) {
            return null;
        }

        File f = new File(dir.getAbsolutePath() + "/" + SESSION);
        byte[] bytes = readBytes(f);

        if (bytes == null) {
            return null;
        }

        try {
            return keyUtil().rawSessionFromBytes(bytes);
        } catch (IOException e) {
            LOGGER.log(Level.SEVERE, "loadRawSession has failed: "+e.getMessage());
            return null;
        }
    }

    @Override
    public HashMap<Integer, T_Sess> loadAllRawSessionsOf(BareJid contact) {
        File dir = getContactsPath();
        HashMap<Integer, T_Sess> sessions = new HashMap<>();

        if (dir == null) {
            return sessions;
        }

        dir = create(new File(dir.getAbsolutePath() + "/" + contact.toString()));
        File[] list = dir.listFiles();

        if (list == null) {
            return sessions;
        }

        for (File f : list) {
            if (!f.isDirectory()) {
                continue;
            }

            try {
                int id = Integer.parseInt(f.getName());
                T_Sess s = loadRawSession(new OmemoDevice(contact, id));

                if (s != null) {
                    sessions.put(id, s);
                }
            } catch (NumberFormatException e) {
                LOGGER.log(Level.WARNING, "loadAllRawSessions has failed for file "
                        +f.getAbsolutePath()+": "+e.getMessage());
            }
        }
        return sessions;
    }

    @Override
    public void storeRawSession(OmemoDevice device, T_Sess session) {
        File dir = getContactDevicePath(device);
        if (dir != null) {
            File f = new File(dir.getAbsolutePath() + "/" + SESSION);
            writeBytes(keyUtil().rawSessionToBytes(session), f);
        }
    }

    @Override
    public void removeRawSession(OmemoDevice device) {
        File dir = getContactDevicePath(device);
        if (dir != null) {
            File f = new File(dir.getAbsolutePath() + "/" + SESSION);
            f.delete();
        }
    }

    @Override
    public void removeAllRawSessionsOf(BareJid contact) {
        File dir = getContactsPath();
        if (dir != null) {
            File f = new File(dir.getAbsolutePath() + "/" + contact.toString());
            f.delete();
        }
    }

    @Override
    public boolean containsRawSession(OmemoDevice device) {
        File dir = getContactDevicePath(device);
        return dir != null && new File(dir.getAbsolutePath() + "/" + SESSION).exists();
    }

    @Override
    public void setDateOfLastReceivedMessage(OmemoDevice from, Date date) {
        File dir = getContactDevicePath(from);
        if(dir == null) {
            return;
        }

        File f = new File(dir.getAbsolutePath() + "/" + LAST_MESSAGE_RECEIVED);

        try {
            writeBytes(Long.toString(date.getTime()).getBytes(StringUtils.UTF8), f);
        } catch (UnsupportedEncodingException e) {
            LOGGER.log(Level.SEVERE, "setDateOfLastReceivedMessage has failed: "+e.getMessage());
        }
    }

    @Override
    public Date getDateOfLastReceivedMessage(OmemoDevice from) {
        File dir = getContactDevicePath(from);
        if(dir == null) {
            return null;
        }

        File f = new File(dir.getAbsolutePath() + "/" + LAST_MESSAGE_RECEIVED);
        if(!f.exists() || !f.isFile()) {
            return null;
        }

        try {
            byte[] b = readBytes(f);

            if(b == null) {
                return null;
            }

            return new Date(Long.valueOf(new String(b, StringUtils.UTF8).trim().replace("\n","")));
        } catch (UnsupportedEncodingException e) {
            LOGGER.log(Level.SEVERE, "getDateOfLastReceivedMessage failed: "+e.getMessage());
            return null;
        }
    }

    @Override
    public void setDateOfLastSignedPreKeyRenewal(Date date) {
        File dir = getDevicePath();
        if(dir == null) {
            return;
        }

        File f = new File(dir.getAbsolutePath() + "/" + LAST_SIGNED_PREKEY_RENEWAL);
        try {
            writeBytes(Long.toString(date.getTime()).getBytes(StringUtils.UTF8), f);
        } catch (UnsupportedEncodingException e) {
            LOGGER.log(Level.SEVERE, "setDateOfLastSignedPreKeyRenewal has failed: "+e.getMessage());
        }
    }

    @Override
    public void purgeOwnDeviceKeys() {
        File dir = getDevicePath();
        if(dir != null) {
            deleteRecursive(dir);
        }
    }

    @Override
    public Date getDateOfLastSignedPreKeyRenewal() {
        File dir = getDevicePath();
        if(dir == null) {
            return null;
        }

        File f = new File(dir.getAbsolutePath() + "/" + LAST_SIGNED_PREKEY_RENEWAL);
        if(!f.exists() || !f.isFile()) {
            return null;
        }

        try {
            byte[] b = readBytes(f);
            if(b != null) {
                return new Date(Long.valueOf(new String(b, StringUtils.UTF8).trim()));
            }
            return null;
        } catch (UnsupportedEncodingException e) {
            LOGGER.log(Level.SEVERE, "getDateOfLastSignedPreKeyRenewal has failed: "+e.getMessage());
            return null;
        }
    }

    @Override
    public CachedDeviceList loadCachedDeviceList(BareJid contact) {
        CachedDeviceList cachedDeviceList = new CachedDeviceList();

        if (contact == null) {
            return null;
        }

        File dir = getContactsPath();
        if (dir == null) {
            return cachedDeviceList;
        }

        dir = create(new File(dir.getAbsolutePath() + "/" + contact.toString()));
        File f = new File(dir.getAbsolutePath() + "/" + DEVICE_LIST);
        byte[] bytes = readBytes(f);

        if (bytes == null) {
            return cachedDeviceList;
        }

        try {
            String s = new String(bytes, StringUtils.UTF8);

            if (!s.contains("a:") || !s.contains("i:")) {
                return cachedDeviceList;
            }

            String a = s.substring(s.indexOf("a:") + 2, s.indexOf("i:"));
            String[] ids = a.split(",");

            for (String id : ids) {
                if(!id.trim().equals("")) {
                    cachedDeviceList.addDevice(Integer.parseInt(id));
                }
            }

            String i = s.substring(s.indexOf("i:") + 2);
            String[] iids = i.split(",");

            for (String iid : iids) {
                if (iid.length() > 0) {
                    cachedDeviceList.getInactiveDevices().add(Integer.parseInt(iid));
                }
            }

            return cachedDeviceList;
        } catch (UnsupportedEncodingException e) {
            LOGGER.log(Level.SEVERE, "loadCachedDeviceList failed: "+e.getMessage());
            return cachedDeviceList;
        }
    }

    @Override
    public void storeCachedDeviceList(BareJid contact, CachedDeviceList deviceList) {
        if (contact == null) {
            return;
        }
        File dir = getContactsPath();

        if(dir == null) {
            return;
        }

        dir = create(new File(dir.getAbsolutePath() + "/" + contact.toString()));

        String s = "a:";
        for (int i : deviceList.getActiveDevices()) {
            s += i + ",";
        }

        if (s.endsWith(",")) {
            s = s.substring(0, s.length() - 1);
        }

        s += "i:";
        for (int i : deviceList.getInactiveDevices()) {
            s += i + ",";
        }

        if (s.endsWith(",")) {
            s = s.substring(0, s.length() - 1);
        }

        File f = new File(dir + "/" + DEVICE_LIST);
        try {
            writeBytes(s.getBytes(StringUtils.UTF8), f);
        } catch (UnsupportedEncodingException e) {
            LOGGER.log(Level.SEVERE, "storeCachedDeviceList has failed: "+e.getMessage());
        }
    }

    /**
     * Return the root path of the OMEMO store.
     *
     * @return path
     */
    private File getOmemoPath() {
        return create(new File(base.getAbsolutePath() + "/omemo"));
    }

    /**
     * Return the OMEMO storage directory of the current user.
     *
     * @return path
     */
    private File getUserPath() {
        return create(new File(getOmemoPath().getAbsolutePath() + "/" + omemoManager.getOwnJid().toString() + "/"));
    }

    /**
     * Return the OMEMO storage path of this device.
     *
     * @return path
     */
    private File getDevicePath() {
        return create(new File(getUserPath() + "/" + omemoManager.getDeviceId()));
    }

    /**
     * Return the OMEMO storage path of the contacts of this device.
     *
     * @return path
     */
    private File getContactsPath() {
        File f = getDevicePath();
        if (f != null) {
            return create(new File(f.getAbsolutePath() + "/contacts"));
        }
        return null;
    }

    /**
     * Return the OMEMO storage path of the contact 'device'.
     *
     * @param device device in question
     * @return path
     */
    private File getContactDevicePath(OmemoDevice device) {
        File dir = getContactsPath();
        if (dir != null) {
            return create(new File(dir.getAbsolutePath() + "/" + device.getJid().toString() + "/" + device.getDeviceId()));
        }
        return null;
    }

    /**
     * Return the OMEMO storage path of the signed preKeys of the user.
     *
     * @return path
     */
    private File getSignedPreKeysPath() {
        File f = getDevicePath();
        if (f != null) {
            return create(new File(f.getAbsolutePath() + "/signedPreKeys"));
        }
        return null;
    }

    /**
     * Return the OMEMO storage path of the normal preKeys of the user.
     *
     * @return path
     */
    private File getPreKeysPath() {
        File f = getDevicePath();
        if (f != null) {
            return create(new File(f.getAbsolutePath() + "/preKeys"));
        }
        return null;
    }

    /**
     * Create the path in the file system.
     *
     * @param path path to create
     * @return path
     */
    public File create(File path) {
        if (!path.exists()) {
            path.mkdirs();
        }
        return path;
    }

    /**
     * Write bytes into file.
     *
     * @param data data
     * @param destination destination file.
     */
    private static void writeBytes(byte[] data, File destination) {
        FileOutputStream fos = null;
        try {

            if (!destination.exists()) {
                destination.createNewFile();
            }

            fos = new FileOutputStream(destination);
            fos.write(data);

        } catch (IOException e) {
            LOGGER.log(Level.SEVERE, "writeBytes has failed to write: "+e.getMessage());
        } finally {

            try {

                if (fos != null) {
                    fos.close();
                }

            } catch (IOException e) {
                LOGGER.log(Level.SEVERE, "writeBytes has failed to close OutputStream: "+e.getMessage());
            }
        }
    }

    /**
     * Read bytes from file.
     *
     * @param from file
     * @return bytes
     */
    private static byte[] readBytes(File from) {
        if (!from.exists()) {
            return null;
        }

        FileInputStream fis = null;

        try {
            fis = new FileInputStream(from);
            byte[] buffer = new byte[(int) from.length()];
            fis.read(buffer);
            return buffer;

        } catch (IOException e) {
            LOGGER.log(Level.SEVERE, "readBytes has failed to read: "+e.getMessage());

        } finally {
            try {
                if (fis != null)
                    fis.close();

            } catch (IOException e) {
                LOGGER.log(Level.SEVERE, "readBytes has failed to close the InputStream: "+e.getMessage());
            }
        }
        return null;
    }

    /**
     * Write integer to file.
     *
     * @param to file
     * @param i int
     */
    private static void writeInt(File to, int i) {
        try {
            writeBytes(Integer.toString(i).getBytes(StringUtils.UTF8), to);
        } catch (UnsupportedEncodingException e) {
            LOGGER.log(Level.SEVERE, "writeInt has failed due to unsupported encoding: "+e.getMessage());
        }
    }

    /**
     * Read integer from file
     *
     * @param from file
     * @return int
     */
    private static int readInt(File from) {
        byte[] bytes = readBytes(from);

        if (bytes == null) {
            return -1;
        }

        try {
            return Integer.parseInt(new String(bytes, StringUtils.UTF8));

        } catch (NumberFormatException | UnsupportedEncodingException e) {
            LOGGER.log(Level.SEVERE, "readInt has failed due to unsupported encoding: "+e.getMessage());
            return -1;
        }
    }

    /**
     * Recursively delete all data except trust decisions from a directory.
     *
     * @param f file or directory
     * @return success
     */
    private static boolean deleteRecursive(File f) {
        if(f == null) {
            return true;
        }

        if(f.isFile()) {
            return f.delete();

        } else {
            boolean deleted = true;
            File[] files = f.listFiles();

            if(files == null) {
                return true;
            }

            for(File f1 : files) {
                deleted &= deleteRecursive(f1);
            }

            return deleted && f.delete();
        }
    }
}
