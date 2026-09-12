# Private Remote Access

## LAN mode

```text
Android -> trusted private Wi-Fi -> PC:8001
```

Set `CCC_API_HOST=0.0.0.0`, keep API authentication enabled, and use the PC's private IPv4 address in Android Settings. Do not use `127.0.0.1` from the phone.

## Remote mode

```text
Android -> private encrypted tunnel -> PC/backend -> paired Windows agent
```

Use a private encrypted tunnel or VPN under the operator's control. Set `CCC_PRIVATE_TUNNEL_ENDPOINT` only to an `https` tunnel endpoint with no embedded credentials. The backend does not provision a tunnel vendor, open router ports, or expose port `8001` publicly.

The automated local private-tunnel integration test validates API authentication, device authorization, telemetry, alerts, timeline, safe actions, audit records, and revocation. It is not a substitute for validating a real VPN/tunnel deployment.

## Tailscale mode

Tailscale supplies private reachability. CCC continues to use its existing
authenticated API on TCP `8001`; no Tailscale SDK is required in the Android
app.

### Windows PC

1. Install Tailscale.
2. Sign in.
3. Confirm the CCC Windows PC appears in the private Tailscale network.
4. Find the PC's current Tailscale IP or Tailscale DNS name.

For access from both the trusted LAN and Tailscale, set these values in the
PC's private `.env` file and restart CCC:

```text
CCC_API_HOST=0.0.0.0
CCC_API_PORT=8001
CCC_AUTH_ENABLED=true
CCC_API_TOKEN=<existing CCC API token>
```

Keep Windows Firewall restricted to the required private network profiles. To
bind only to the current Tailscale IPv4 interface, `CCC_API_HOST` may instead
be set to that current `100.64.0.0/10` address. Do not hardcode a Tailscale
address in the application; it can change.

### Android

1. Install Tailscale.
2. Sign in to the same private Tailscale network.
3. Enable the Tailscale VPN connection.
4. Open CCC Android Settings.
5. Enter the Windows PC's current Tailscale IP or Tailscale DNS name with `:8001`.
6. Enter the existing CCC API token.
7. Save and test the connection.

The backend URL remains editable in Settings. The token is stored using the
Android Keystore and sent as `Authorization: Bearer <token>`. An invalid token
must remain an authentication error; an unavailable backend remains a network
failure state.

### Security requirements

- Never port-forward TCP `8001`.
- Never expose CCC management APIs directly to the public internet.
- Use the private Tailscale network for remote reachability.
- Keep CCC authentication, authorization, rate limiting, auditing, pairing,
  revocation, and device identity enabled.

The local private-remote integration test does not validate a real Tailscale
network. Real Android-to-Tailscale-to-CCC validation remains an external test.
