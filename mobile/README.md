# BELTU Mobile Command Center

Flutter client for the authenticated BELTU Remote Operations gateway.

## Build target URL

```bash
flutter run --dart-define=BELTU_BASE_URL=http://10.0.2.2:8765
```

Use `10.0.2.2` for an Android emulator talking to a host-local gateway. Use the server's private LAN address only on a trusted network with the gateway configured and protected accordingly.

The app stores the BELTU access token in platform secure storage, uses HTTPS/WSS when the base URL is HTTPS, subscribes to live events, and keeps policy/state on the server.
