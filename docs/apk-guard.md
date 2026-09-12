# APK Guard

APK Guard performs static analysis only. Uploaded APK bytes are hashed and inspected as ZIP content. APKs are never executed.

Checks include:

- SHA-256
- manifest package/version fields where detectable
- SDK fields where detectable
- permissions
- Android components
- exported components
- debuggable and backup flags
- cleartext traffic flag
- certificate/signature file hints

Upload protections:

- File name is sanitized.
- Only `.apk` names are accepted.
- Size is limited.
- Oversized uploads are rejected from the request header when possible before body processing.
- Malformed ZIP/APK content is rejected.
- No shell execution is used.

Findings are defensive and explainable. A permission alone is not treated as proof of malware.
