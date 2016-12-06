# SDF API


The SDF API (GM/T 0018-2012) is the cryptographic API of C language for PCI-E
cryptographic cards. Here we introduce the specific design of the SDF API and
our implementation choices.

## Device

When open or connect to a device, the caller can not specify the device name or
any information for a specific device. Thus if the opened device is not the
only device installed on the current host machine, it will be the default one.
So it seems that returning the opened handler is not necessary because the
library should handle this.

	int SDF_OpenDevice(void **phDeviceHandle);

For software implementation, the library-level initialization can be performed
here.

There is a strange design in SDF:

	int SDF_GetDevideInfo(void *hSessionHandle, DEVICEINFO *pstDeviceInfo);

The session handle is required. There will be no different for sessions to get
device info, and the caller should get device info without opening a session,
when there is no session-level access control.

So the GmSSL implementation will omit the `hSessionHandle` argument.

## Session

Nearly all the functions require a session handle as the first argument. A
sesson can be seen as a connection from the host to the PCI-E card. For some of
the PCI-E card such as the Intel Xeon Phi, the host use a socket to
communicated the operating system inside the PCI-E card. So a session handle in
the SDF API might be a wrapping of a socket, a file handler or some other data
structures.

The session handle is used as context for the following operations:

* Hash operations
* File operations

It is strange that the encrypt, mac does not provide stream oeprations.


## Access Control

The SDF API provides key level access control with password authentication.
This means that if not using shared passwords, the application has to manage
multiple passwords for different keys. For interfaces such as PKCS #11, there
is only one password for user-level to access the token, but for the SDF, this
also means that the user as a person can not remember all these passwords, but
the application need to provide password and key management utilities. As the
typical application scenario is a VPN server or a HTTPS proxy, these passwords
can be configured in files.

Related functions:

	SDF_GetPrivateKeyAccessRight
	SDF_ReleasePrivateKeyAccessRight

## Key Reference

In SDF API the crpytographic keys are referenced through key index integer and
a opaque key handler.

## Data Storage

The SDF device can provide some data storage.

	SDF_CreateFile
	SDF_ReadFile
	SDF_WriteFile
	SDF_DeleteFlile

The files are not protected by access control.

