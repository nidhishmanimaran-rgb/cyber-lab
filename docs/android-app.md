# Android App

The native Kotlin app is in:

```text
android/CyberCommandCenter/
```

The Samsung M02 is only a dashboard/control device. The PC remains the analysis engine.

Features:

- configurable backend URL
- API token field for `Authorization: Bearer ...`, encrypted with the Android Keystore
- overall risk
- active alerts count
- recent events count
- device count
- APK and WebSec result counts
- offline, timeout, wrong IP, and API error messaging

For LAN use:

1. Set `CCC_API_HOST=0.0.0.0`.
2. Restart the backend.
3. Allow Windows Firewall access on private networks only.
4. Use `http://<PC-LAN-IP>:8001` in the app, for example `http://192.168.1.7:8001`.

The app is build-ready from `android/CyberCommandCenter`. Point it at the PC's LAN address, not `127.0.0.1`, when using the same Wi-Fi network. Build a debug APK with:

```powershell
.\gradlew.bat :app:assembleDebug --no-daemon --console=plain
```

The release build type is available for operator signing. No signing key is stored in this repository.
