# Insecure Deserialization & XXE

Deserialization vulnerabilities occur when untrusted data is converted back into
objects without validation. In the worst cases they enable remote code execution
by triggering gadget chains in the deserialization library itself — before any
application code runs.

XXE (XML External Entity) injection is a related class: a malicious XML document
references an external entity, causing the parser to read local files, make internal
network requests, or in some parsers execute code.

Load `references/lang/<lang>.md` for language-specific safe and unsafe patterns.

---

## Deserialization

### Risk by Format

| Format | Risk level | Notes |
|--------|-----------|-------|
| Python `pickle` / `marshal` | **Critical** | Arbitrary code execution by design; never deserialize untrusted input |
| Java `ObjectInputStream` | **Critical** | Gadget chains widely available; billions of CVEs stem from this |
| PHP `unserialize()` | **Critical** | Gadget chains in most major frameworks |
| .NET `BinaryFormatter` | **Critical** | Deprecated in .NET 9; remove all usage |
| .NET `NetDataContractSerializer` | **Critical** | Same issues as BinaryFormatter |
| Ruby `Marshal.load` | **Critical** | Arbitrary code execution |
| YAML (most libraries) | **High** | Most default parsers allow type instantiation |
| JSON | **Low** | Safe to parse; unsafe if result is used to instantiate arbitrary types |
| Protobuf / MessagePack | **Low** | Safe if schema is enforced; type confusion possible without it |
| XML | **Medium** | Safe if XXE disabled; see XXE section below |

### The Core Rule

Never deserialize data from an untrusted source using a format that supports
arbitrary object instantiation. For serialized objects crossing a trust boundary,
use a data-only format (JSON, Protobuf) with explicit schema validation.

### JSON is Not Automatically Safe

JSON parsing is safe. What you do with the parsed data may not be:
- Passing a parsed type hint from the JSON to a class loader: unsafe
- `JSON.parse` + constructing objects based on a `type` field: potential type confusion
- Libraries with polymorphic deserialization enabled (Jackson `enableDefaultTyping`,
  Newtonsoft.Json `TypeNameHandling.All`): unsafe

```
UNSAFE (Jackson):
  objectMapper.enableDefaultTyping();
  objectMapper.readValue(json, Object.class);

SAFE:
  objectMapper.readValue(json, SpecificDto.class);

UNSAFE (Newtonsoft.Json):
  JsonConvert.DeserializeObject(json, new JsonSerializerSettings {
      TypeNameHandling = TypeNameHandling.All
  });

SAFE:
  JsonConvert.DeserializeObject<SpecificDto>(json);
```

### YAML

Most YAML libraries default to full deserialization including type instantiation.

```
UNSAFE (Python):  yaml.load(data)              → arbitrary object construction
SAFE   (Python):  yaml.safe_load(data)          → data types only

UNSAFE (Go):      yaml.Unmarshal(data, &any{})  → interface{} allows type tags
SAFE   (Go):      yaml.Unmarshal(data, &MyStruct{})  → known type only

UNSAFE (JS):      js-yaml load() with schema allowing JS types
SAFE   (JS):      js-yaml load() with SAFE_SCHEMA (default in modern versions)
```

### Integrity Signing (When You Must Serialize Objects)

If you control both ends of the serialization (e.g., a signed cookie or a JWT), you
can use native serialization safely by signing the payload and verifying the signature
before deserializing:

1. Serialize → sign with HMAC-SHA256 using a secret key → transmit
2. Receive → verify signature before deserializing → deserialize only if valid

This does not make the format inherently safe — it only prevents tampering by
outsiders. Never apply this pattern to data from third parties.

---

## XXE (XML External Entity Injection)

XML parsers can be configured to resolve external entities — references to files
or URLs embedded in the XML document. When a parser does this with untrusted XML:

- **File disclosure:** `<!ENTITY xxe SYSTEM "file:///etc/passwd">` reads local files
- **SSRF:** `<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">` reaches
  internal services (AWS instance metadata, Azure IMDS, internal APIs)
- **DoS (Billion Laughs):** Exponentially expanding entity references exhaust memory

### The Fix: Disable External Entities

Every XML parser that processes untrusted input must have external entity resolution
disabled. The exact setting differs by library:

**The pattern is the same in every language:**
find the parser configuration option that controls external entity resolution
and set it to disabled/false/secure mode before parsing any untrusted document.

Language-specific configuration is in `references/lang/<lang>.md`.

### SVG, DOCX, XLSX, PDF, and RSS

These formats are XML-based or embed XML. File upload endpoints that accept these
formats are XXE-vulnerable if the parser doesn't disable external entities:

- **SVG uploads:** common XXE vector; parse with external entities disabled
- **DOCX/XLSX:** ZIP containing XML; parse with external entities disabled
- **PDF (some parsers):** may contain XML streams
- **RSS/Atom feeds:** fetch and parse server-side with XXE protections

If you do not need to parse XML at all (e.g., only storing and re-serving the file),
do not parse it — avoid the risk entirely.

---

## Deserialization / XXE Review Checklist

- [ ] No `pickle.loads`, `marshal.loads` on untrusted data (Python)
- [ ] No `ObjectInputStream.readObject` on untrusted data (Java)
- [ ] No `BinaryFormatter.Deserialize` anywhere (C# — deprecated, remove all usage)
- [ ] No `TypeNameHandling.All` or `enableDefaultTyping` in JSON config
- [ ] `yaml.safe_load` used instead of `yaml.load` (Python)
- [ ] All XML parsers configured to disable external entities and DTD processing
- [ ] File upload endpoints accepting XML-based formats (SVG, DOCX, XLSX) use safe parser config
- [ ] Serialized objects crossing trust boundaries are signed and signature verified before deserialization
- [ ] JSON deserialization targets specific known types, not `Object` or `any`
