# Recipient-Locked Encryptor (Rust, Windows/Desktop)

This app is designed so one device can encrypt a file specifically for another selected device.

## Model
- Each device generates its own X25519 keypair.
- Public keys can be exported/imported between devices.
- File content uses AES-256-GCM-SIV chunk encryption.
- A random file key is wrapped for the recipient using X25519-derived shared secret + AES-256-GCM-SIV.
- Only the device with the matching private key can unwrap the file key and decrypt the content.

## Typical flow
1. On device B, click `Generate this device keypair`.
2. On device B, click `Export my public key` and send the JSON public key file to device A.
3. On device A, click `Import recipient public key` and choose B's exported public key JSON.
4. On device A, select a file and click `Encrypt for recipient`.
5. Send the resulting `.2brecip` file to device B.
6. On device B, select that `.2brecip` file and click `Decrypt on this device`.

## Notes
- This version stores the private key in `device_keys/identity.json` next to the app working directory. That means it is not yet TPM-backed or hardware-protected.
- It is already much closer to the required recipient-only model than a DPAPI-only design.
- Future hardening: store private key in Windows protected storage or TPM, add recipient management list, sign public keys, add authenticated header binding.
