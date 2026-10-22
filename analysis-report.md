# Static Analysis Report: Encoded PowerShell Loader

**Case ID:** LAB-PS-001  
**Analysis date:** 22 October 2026  
**Analyst role:** Student / beginner DFIR lab  
**Tool:** CyberChef (web interface)  
**Analysis type:** Static analysis only  
**Sample execution:** Not performed

## 1. Executive summary

A supplied command launches PowerShell with a hidden window and an encoded command. Decoding the outer Base64 content as UTF-16LE reveals a script that loads a second Base64-encoded object into a memory stream and decompresses it with GZip. The decompressed PowerShell text includes dynamic Windows API lookup and memory-related operations, including references to `GetProcAddress`, `VirtualAlloc`, and `Marshal::Copy`, followed by delegate invocation and a conditional execution path.

The combination is consistent with a loader that prepares or invokes code in memory. This conclusion is based on the visible static code. The analysis did not execute the sample and did not establish the final payload's capabilities, successful execution, or compromise of any endpoint.

## 2. Scope and methodology

The scope was limited to decoding and reviewing the supplied command using CyberChef. No payload execution, network access by the sample, sandbox detonation, endpoint acquisition, or live-system testing was performed.

### Procedure

1. Decoded the value supplied to `-encodedcommand` using `From Base64` and `Decode text` configured for UTF-16LE.
2. Identified a nested Base64 string passed to `.FromBase64String(...)`.
3. Decoded the nested string with `From Base64` and decompressed it with `Gunzip`.
4. Reviewed the resulting text for execution logic, Windows API references, and memory-related behavior.

## 3. Findings

### Finding 1 — Concealed and encoded PowerShell launch

**Observed evidence:** The original command contains `-nop`, `-w hidden`, and `-encodedcommand`.

**Interpretation:** `-nop` is commonly used as an abbreviation for `-NoProfile`; `-w hidden` requests a hidden window; and `-encodedcommand` supplies a Base64-encoded PowerShell command. These options can have legitimate uses, but in combination with nested compression and memory-related code they increase suspicion.

**Confidence:** High that the options appear in the supplied command. The options alone do not prove maliciousness.

### Finding 2 — Nested Base64 and GZip decoding

**Observed evidence:** The first decoded layer creates a `System.IO.MemoryStream` using `Convert::FromBase64String(...)` and passes it to `System.IO.Compression.GZipStream` for decompression.

**Interpretation:** The command uses multiple layers to conceal the next script stage. The embedded Base64 begins with `H4sI`, which is consistent with a GZip stream represented in Base64; successful decompression in CyberChef further supports that interpretation.

**Confidence:** High for the visible decoding/decompression logic.

### Finding 3 — Dynamic Windows API resolution and memory operations

**Observed evidence in the decompressed output:** References include `GetProcAddress`, `VirtualAlloc`, `System.Runtime.InteropServices.Marshal::Copy`, delegate construction/invocation, and a buffer length passed to a memory allocation call.

**Interpretation:** The script appears to resolve Windows API functions dynamically and prepare data in allocated memory. Such patterns are consistent with shellcode loaders or other in-memory execution mechanisms. The visible excerpt does not by itself prove exactly what bytes were placed in memory or whether the call succeeded.

**Confidence:** High that these references appear in the recovered text; moderate for the loader/shellcode interpretation; insufficient to determine the final payload's purpose.

### Finding 4 — Dynamic PowerShell execution

**Observed evidence:** The script assigns text to `$DoIt` and includes `IEX $DoIt`. A conditional branch also contains `start-job { param($a) IEX $a ... }`.

**Interpretation:** `IEX` is the PowerShell alias for `Invoke-Expression`, which evaluates a string as PowerShell code. This is a dynamic execution mechanism and is risky when the executed content is decoded or constructed at runtime.

**Confidence:** High for the code pattern; runtime success was not tested.

## 4. Behavioral assessment

The strongest evidence is the combination of:
- hidden and encoded PowerShell invocation;
- a nested Base64/GZip stage;
- dynamic PowerShell evaluation;
- dynamic Windows API resolution and memory operations.

Together, these behaviors are consistent with a **PowerShell-based in-memory loader or shellcode-execution pattern**. This is a static behavioral classification, not a confirmed malware-family identification.

## 5. Indicators for hunting

### Behavioral strings observed

- `-encodedcommand`
- `-w hidden`
- `FromBase64String`
- `GZipStream`
- `GetProcAddress`
- `VirtualAlloc`
- `Marshal::Copy`
- `IEX` / `Invoke-Expression`
- `RunAs32`

These are not unique identifiers and can produce false positives. They should be used to guide contextual investigation rather than treated as standalone proof.

### Network and host IOCs

No verified domain, URL, IP address, file hash, registry key, or persistence artifact was established from the screenshots reviewed. No IOC should be invented or reported as confirmed.

## 6. MITRE ATT&CK mapping (tentative)

| Technique | Rationale | Qualification |
|---|---|---|
| T1059.001 — PowerShell | PowerShell is used for the decoded script and dynamic evaluation. | Behavior visible in code; actual execution is unconfirmed. |
| T1027 — Obfuscated Files or Information | Base64 encoding and GZip compression conceal script content. | The observed layers support this mapping. |

No stronger claim is made for process injection, persistence, defense evasion, command-and-control, credential access, or exfiltration because the current evidence does not establish those behaviors.

Reference: https://attack.mitre.org/

## 7. Risk and impact

If executed successfully in a real environment, a script using this type of in-memory loading pattern could potentially run additional code while leaving fewer conventional payload files on disk. The actual impact depends on the hidden code, execution context, privileges, host controls, and any subsequent behavior.

This lab does not show that the sample was executed or that a real system was compromised. No organization-specific impact can be concluded from the command alone.

## 8. Recommended response actions for a real incident

1. Preserve the original command line, timestamp, source, and relevant endpoint telemetry.
2. Correlate process-creation events with parent process, user, host, and surrounding activity.
3. Review PowerShell operational logs and Script Block Logging where available and authorized.
4. Review EDR telemetry for suspicious memory allocation, API resolution, script execution, and process relationships.
5. Correlate with DNS, proxy, firewall, identity, and network records if relevant indicators are discovered.
6. Follow the organization's incident-response process for containment and evidence preservation; do not make disruptive changes without authorization.
7. Record hashes, collection details, timestamps, and chain of custody if handling a real incident.
8. Avoid concluding that compromise occurred based only on suspicious code; validate with independent telemetry.

## 9. Limitations

- Only screenshots of the CyberChef output were available for this report.
- The complete recovered script was not independently parsed line by line.
- No execution or sandbox analysis was conducted.
- No endpoint, process, network, or memory telemetry was provided.
- No attribution or malware-family identification was attempted.
- No claim is made that the sample reached a victim, executed successfully, persisted, communicated externally, or exfiltrated data.

## 10. Conclusion

The supplied command contains multiple layers of encoding/compression and recovered code with dynamic execution and Windows memory/API operations. The evidence supports treating it as suspicious and consistent with an in-memory loader pattern. Further conclusions require the complete artifact and independent telemetry, analyzed in an authorized isolated environment by an appropriately equipped response team.

## References

- CyberChef: https://gchq.github.io/CyberChef/
- Microsoft PowerShell documentation: https://learn.microsoft.com/powershell/
- MITRE ATT&CK: https://attack.mitre.org/
