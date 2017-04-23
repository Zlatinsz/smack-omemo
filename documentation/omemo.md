Encrypting messages with OMEMO
==============================

[Back](index.md)

OMEMO ([XEP-0384](https://xmpp.org/extensions/xep-0384.html)) is an adaption
of the Signal protocol for XMPP. It provides an important set of
cryptographic properties including but not restricted to

* Confidentiality
* Integrity
* Authenticity
* Forward secrecy
* Future secrecy (break-in recovery)
* Plausible deniability

Contrary to OTR it is capable of mutli-end-to-multi-end encryption and
message synchronization across multiple devices. It also allows the sender
to send a message while the recipient is offline.

It does NOT provide a server side message archive, so that a new device could
fetch old chat history.

Most implementations of OMEMO use the signal-protocol libraries provided by
OpenWhisperSystems. Unlike Smack, those libraries are licensed under the GPL,
which prevents a Apache licensed OMEMO implementation using those libraries (see
[licensing situation](https://github.com/igniterealtime/Smack/wiki/OMEMO-libsignal-Licensing-Situation)).
The module smack-omemo therefore contains no code related to signal-protocol.
However, almost all functionality is capsulated in that module. If you want
to use OMEMO in a GPL client, you can use the smack-omemo-signal
Smack module, which binds the signal-protocol library to smack-omemo.
It is also possible, to port smack-omemo to other libraries implementing the
double ratchet algorithm.

Requirements
------------

In order to use OMEMO encryption, your server and the servers of your chat
partners must support PEP ([XEP-0163](http://xmpp.org/extensions/xep-0163.html)) 
to store and exchange key bundles.
Optionally your server should support Message Carbons ([XEP-0280](http://xmpp.org/extensions/xep-0280.html))
and Message Archive Management ([XEP-0313](http://xmpp.org/extensions/xep-0313.html))
to achieve message synchronization across all (on- and offline) devices.

Dependencies
------------

If you want to use smack-omemo-signal in your project, make sure to include the following dependencies:

- bcprov-jdk15on-156.jar
- curve25519-java-0.3.0.jar
- protobuf-java-2.5.0.jar
- signal-protocol-java-2.4.0.jar

You also need to include the following smack-modules in your project:

- smack-core
- smack-experimental
- smack-extensions
- smack-im
- smack-java7

Setup
-----

On first start, you have to set a security provider like bouncycastle.
Also the client has to initialize the providers.

```
Security.addProvider(new BouncyCastleProvider());
new OmemoInitializer().initialize();
```

Next you can get an OmemoManager object, which can be used to execute OMEMO
related actions like sending a message etc.

```
OmemoManager omemoManager = OmemoManager.getInstanceFor(connection);
```

You also need an OmemoStore implementation that will be responsible for storing
and accessing persistent data. You can either use a FileBasedOmemoStore, or
implement your own (eg. using an SQL database etc). Last but not least, you need
an implementation of the OmemoService that handles events. Note, that the store
and service are dependent on the library used for the double ratchet, so in this
example, I assume, that you use smack-omemo together with smack-omemo-signal.

```
SignalOmemoStore omemoStore = new SignalFileBasedOmemoStore(omemoManager, path);
SignalOmemoService omemoService = new SignalOmemoService(omemoManager, omemoStore);
```

The next step is to start the setup method of the service. This will subscribe the service to OMEMO device lists, upload the bundle and so on.
Note, that this method does some heavy work on the network.

```
omemoManager.initialize();
```

At this point, the module has already generated some keys and announced OMEMO support.
To get updated with new OMEMO messages, you should register message listeners.

```
omemoManager.addOmemoMessageListener(myOmemoMessageListener);
omemoManager.addOmemoMucMessageListener(myOmemoMucMessageListener);
```

Usage
-----

You may want to generate a new identity sometime in the future. Thats pretty straight
forward. No need to manually publish bundles etc.

```
omemoManager.regenerate();
```

In case your device list gets filled with old unused identities, you can clean it up.
This will remove all active devices from the device list and only publish the device
you are using right now.

```
omemoManager.purgeDevices();
```

If you want to find out, whether a server, MUC or contacts resource supports OMEMO,
you can use the following methods:

```
boolean serverCan = omemoManager.serverSupportsOmemo(serverJid);
boolean mucCan = omemoManager.multiUserChatSupportsOmemo(mucJid);
boolean resourceCan = omemoManager.resourceSupportsOmemo(contactsResourceJid);
```

To encrypt a message for a single contact or a MUC, you do as follows:

```
BareJid singleContact;
Message message = new Message("Hi!");
ArrayList<BareJid> mucContacts = muc.getOccupants().stream().map(e ->
    muc.getOccupant(e.asEntityFullJidIfPossible()).getJid().asBareJid())
    .collect(Collectors.toCollection(ArrayList::new));

Message encryptedSingleMessage = omemoManager.encrypt(singleContact, message);
Message encryptedMucMessage = omemoManager.encrypt(mucContacts, message);
```

It should be noted, that before you can encrypt a message for a device, you have to trust
its identity. smack-omemo will throw an UndecidedOmemoIdentityException whenever you try
to send a message to a device, which the user has not yet decided to trust or untrust.
To decide about whether a device is trusted or not, you'll have to store some information
in the OmemoStore.

```
omemoStore.trustOmemoIdentity(trustedDevice, trustedIdentityKey);
omemoStore.distrustOmemoIdentity(untrustedDevice, untrustedIdentityKey);
```

The trust decision should be made by the user based on comparing fingerprints.
You can get fingerprints of your own and contacts devices:

```
String myFingerprint = omemoManager.getFingerprint();
String otherFingerprint = omemoStore.getFingerprint(otherDevice);

//Splits the fingerprint in blocks of 8 characters
String prettyFingerprint = omemoStore.keyUtil().prettyFingerprint(myFingerprint);
```

It might happen, that the server you or your contact are using is not delivering devicelist updates correctly.
In such a case smack-omemo cannot fetch bundles or send messages to devices it hasn\'t seen before. To mitigate this, it
might help to explicitly request the latest device list from the server.
```
omemoManager.requestDeviceListUpdateFor(contactJid);
```

If you want to decrypt a MamQueryResult, you can do so using the following method:
````
List<ClearTextMessage> decryptedMamQuery = omemoManager.decryptMamQueryResult(mamQueryResult);
````
Note, that you cannot decrypt an OMEMO encrypted message twice for reasons of forward secrecy.
A ClearTextMessage contains the decrypted body of the message, as well as additional information like if/how the message was encrypted in the first place.
Unfortunately due to the fact that you cannot decrypt messages twice, you have to keep track of the message history locally on the device and ideally also keep track of the last received message, so you can query the server only for messages newer than that.


Configuration
-------------
smack-omemo has some configuration options that can be changed on runtime by changing values in `util.OmemoConstants`:

* setCombinedMessageKeyAuthTag mitigates a security vulnerability found in an independent audit of the OMEMO protocol. This SHOULD stay set to true.
* setIgnoreStaleDevices when set to true, smack-omemo will stop encrypting messages for **own** devices that have not send a message for some period of time (configurable in IGNORE_STALE_DEVICE_AFTER_HOURS)
* setDeleteStaleDevices when set to true, smack-omemo will remove own devices from the device list, if no messages were received from them for a period of time (configurable in DELETE_STALE_DEVICE_AFTER_HOURS)
* setRenewOldSignedPreKeys when set to true, smack-omemo will periodically generate and publish new signed prekeys. Via RENEW_OLD_SIGNED_PREKEYS_AFTER_HOURS you can configure, after what period of time new keys are generated and MAX_NUMBER_OF_STORED_SIGNED_PREKEYS allows configuration of how many prekeys are kept in storage for decryption of delayed messages.
* setAddOmemoBodyHint when set to true, a plaintext body with a hint about OMEMO encryption will be added to the message. This hint will be displayed by clients that do not support OMEMO.
* setAddEmeEncryptionHint when set to true, an Explicit Message Encryption element will be added to the message. This element tells clients, that the message is encrypted with OMEMO.
* setAddMAMStorageProcessingHint when set to true, a storage hint for Message Archive Management will be added to the message. This enabled servers to store messages that contain no body.

Features
--------
* decryption and encryption of OMEMO messages (single and multi user chat)
* provides information about trust status of incoming messages
* automatic publishing of bundle
* automatic merging of incoming deviceList updates
* ignores stale devices after period of inactivity
* removes stale devices from device list after period of inactivity
* automatic repair of broken sessions through ratchet update messages
* automatic renewal of signed preKeys

Copyright (C) Jive Software 2002-2008
