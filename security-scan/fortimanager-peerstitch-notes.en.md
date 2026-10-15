# FortiManager Compromise and the PEERSTITCH Implant (Primary Source)

日本語: [`fortimanager-peerstitch-notes.ja.md`](fortimanager-peerstitch-notes.ja.md)

Analysis of Unit 42's real-incident report **"Unit 42 Uncovers PEERSTITCH, a Stealthy FortiGate
Implant"** (published 2026-10-14). **This incident involves no AI-agent participation whatsoever** —
it is a traditional APT-style intrusion. It fits neither of this repository's two main axes ("AI as
attacker" or "the LLM system as target"), but the pattern — **a centralized management platform's
compromise cascading to a large number of downstream devices** — overlaps substantially with the
Gambit chain's step ⑥ (over-broad permissions) and this repository's observation points, so it is
documented as its own file.

> Same policy: **limited to detection/defense design**. No attack execution steps, weaponization, or
> safety-bypass techniques. The YARA rule's regex/byte patterns are not transcribed here — see the
> original Unit 42 article. Per this repository's existing policy, IOCs (IP addresses, etc.) are not
> transcribed here either (see Tables 3/4 in the original).

## 1. Overview

- Target: a telecommunications managed service provider. Unit 42 tracks the September 2024 intrusion
  as cluster **CL-STA-0954** (aka UNC5820).
- Initial compromise: the centralized management appliance, **FortiManager**, exploited via
  **CVE-2024-47575** (aka FortiJump).
- From that single appliance, an archive was exfiltrated containing the running configurations,
  cryptographic material and databases for **over 500 downstream FortiGate firewalls** — devices
  protecting both the victim's own infrastructure and **its clients' networks**.
- The intrusion proceeded through long-term access, network traffic interception, VPN session
  establishment, backdoor deployment, and exploitation of a second privilege-escalation vulnerability
  (**CVE-2025-61624**), culminating in deployment of a novel memory-resident malware, **PEERSTITCH**.

## 2. The Intrusion Timeline

### 2.1 Initial Compromise and Network Configuration Theft (CVE-2024-47575)

- CVE-2024-47575 (FortiJump) lets an unauthenticated remote attacker execute arbitrary commands via
  crafted requests to the FMG-Access (TCP 541) management channel.
- The attackers registered a rogue virtual FortiGate device named `localhost` (serial number
  `FMG-VMTM23017412`) to the FortiManager instance, from external attacker infrastructure.
- Immediately after device registration, they generated and exfiltrated a configuration archive named
  `.tm`, containing:
  - The FortiManager appliance's own serial number and its management relationships to every enrolled device
  - Complete running configuration files for **over 500 managed FortiGate firewalls**
  - Central management SQLite databases (`global.db`: administrative domains, global objects, policy
    packages; `revinfo.db`: device revision metadata)
  - A list of over 500 FortiGate serial numbers paired with their public IP addresses
  - Internal network topology maps, routing tables and interface configurations
  - Ciphertext administrative, local and SSL/VPN credentials
  - Encoded cryptographic trust material, including public certificates and private keys

### 2.2 Reconnaissance and Traffic Interception

- Using the compromised FortiManager, the attackers pushed **unauthorized sniffer configurations** to
  multiple downstream FortiGate firewalls.
- These targeted unencrypted HTTP traffic and 11 specific ports (Telnet control, license management,
  control panel, and more) to intercept credentials and map network perimeters.
- A later reconnaissance phase added packet-capture rules targeting TFTP (UDP 69), RADIUS/
  RADIUS-Accounting (UDP 1812/1813) and LDAP (TCP 389) on core perimeter firewalls.

### 2.3 Credential Decryption and Re-Entry

- The credentials in the exfiltrated configurations were stored as **reversible ciphertext**, and the
  attackers successfully brute-forced them.
- With the recovered legitimate credentials, they established **unauthorized SSL/VPN sessions** to
  perimeter firewalls from external staging infrastructure, gaining authenticated access to internal
  management segments.

### 2.4 Privilege Escalation (CVE-2025-61624) and PEERSTITCH Deployment

- CVE-2025-61624 is a **path-traversal** vulnerability in FortiOS's `system.auto-script` feature: the
  auto-script object name is not sanitized, so a name containing traversal sequences like
  `../../../../setup` can place the script body anywhere on the filesystem. The script then executes
  with the privileges of the auto-script engine (root).
- This escalates from FortiOS administrative access (including `super_admin`, which has no shell or
  direct filesystem access) to root on the underlying OS, since the daemons implementing FortiOS run
  as root beneath that restricted CLI.
- This path was used to deliver PEERSTITCH's initial-stage loader.

## 3. Technical Analysis of the PEERSTITCH Implant

- A **64-bit Linux ARM64 executable**, written in C and statically linked against glibc. It leaves no
  persistent binary on disk, opens no listening ports, and initiates no outbound connections itself
  (making it resistant to conventional endpoint/network detection) — a **one-shot, memory-patching
  process injector**.
- It targets two core FortiOS daemons: `/bin/miglogd` (system/traffic logging) and `/bin/iked`
  (IKE/IPsec VPN service).
- **Delivery chain**: the `../../../../setup` script pushed via CVE-2025-61624 downloaded five files
  from attacker infrastructure (an environment-prep script, an Emscripten JS/WASM runtime, a
  deployment-orchestrator script, and the ARM64 ELF injector core), then executed them.
- **Process parasitization**: it scans `/proc/` to find the PIDs of both daemons, reads
  `/proc/<pid>/maps` to find their memory layout, attaches via `ptrace(PTRACE_SEIZE)`, captures
  register state, then uses the `mmap` syscall to allocate a 16 KB RWX (read/write/execute) memory
  region at runtime and writes a 1,344-byte injection payload into it.
- **Covert inter-daemon IPC**: rather than network sockets or disk files, it builds a channel that
  passes data **directly between the two daemons' memory**. Each hooked daemon inspects traffic it
  already processes for two markers — a TCP port number (8550) and an IP address (169.254.0.1, a
  link-local address) — and when found, extracts a session token and writes it directly into the
  counterpart daemon's memory via `/proc/<counterpart_pid>/mem`. When `iked` finds a matching tag, it
  takes an alternate execution branch that bypasses FortiOS's default security validation.
- **Tamper suppression**: direct NOP patches (ARM64 `MOV X0, X0`) at three static offsets alter default
  behavior, and a 20-byte trampoline patch redirects execution into the allocated RWX hook buffer.

## 4. Apache mod_md (ACME) Reverse-Shell C2

- Alongside PEERSTITCH, the attackers weaponized FortiGate's built-in Apache `mod_md` module (for
  automated certificate management via the ACME protocol).
- They pushed an auto-script object creating `../../tmp/apache2/conf/md-acme.conf`, injecting a
  malicious configuration that routes ACME directory requests to attacker-controlled infrastructure.
- They injected a **shell command into the domain name field** of a DNS-01 challenge request, exploiting
  `MDChallengeDns01` being mapped to `/bin/node`, to initiate an SSH-based reverse shell.
- Setting `MDRenewMode always` forced Apache to continuously **re-trigger this malicious renewal
  challenge**, maintaining a persistent outbound reverse-shell channel.

## 5. Management-Platform Impersonation (FortiGate-to-FortiManager Chaining)

- FGFM (FortiGate-to-FortiManager communication, TCP 541) is validated against cryptographic trust
  material tied to device serial numbers. The archive exfiltrated in the initial compromise contained
  this material, along with every downstream device's serial number and management relationships.
- Over FGFM from external infrastructure, an administrative account named `FortiGateCloud` — which the
  victim organization had never provisioned, since it operated no FortiManager Cloud tenant —
  downloaded complete configurations from multiple managed firewalls.
- Unit 42 assesses with medium confidence that the attackers impersonated the management platform,
  either by exploiting CVE-2024-26009 (an FGFM authentication bypass using the FortiManager's serial
  number) or by directly reusing the stolen trust material, or both.

## 6. Anti-Forensics and Defense Evasion

- `killall -9 miglogd` / `killall -9 syslogd` to halt log generation before running malicious
  auto-scripts.
- `diagnose debug crashlog clear` to wipe crash logs generated during memory-injection attempts.
- Rogue administrator accounts, VPN groups and auto-script objects were automatically deleted shortly
  after execution.
- `md-acme.conf` was overwritten with a common, innocuous-looking string to mask the reverse-shell
  configuration.
- `lldprx` (the injector) unlinks its own binary from disk after execution and scans `/proc/` to
  terminate the staging process before exiting.
- Log telemetry across the tunnel management interface showed intermittent drops during the malicious
  activity window. Unit 42 assesses with medium confidence that this was deliberate (possibly via
  CVE-2024-26008), though the triggering traffic itself was not captured, so the mechanism is
  unconfirmed.

## 7. Detection Opportunities (summarized from Unit 42's Table 2)

| Detection surface | Artifact/indicator |
|---|---|
| Volatile memory | An anonymous 16 KB region with `rwxp` permissions in `/proc/<pid>/maps` for `miglogd`/`iked` |
| Daemon integrity | NOP patches (`MOV X0, X0`) at three specific static offsets |
| System calls | `open()`/`write()` against `/proc/<pid>/mem` occurring between miglogd and iked |
| Diagnostic logs | Signal 11 (segfault) crashes for miglogd/iked/syslogd in `diagnose debug crashlog read` |
| Configuration audit | `system.auto-script` object names containing path-traversal strings (`../../`) |

## 8. Connections to This Repository's Existing Framework

| Element | Observation point | This repo's detection |
|---|---|---|
| One management-platform compromise cascading to 500+ devices | Concentration of over-broad permission/trust | Same pattern as Gambit chain step ⑥ (over-broad permissions). A concrete case for treating the management platform itself as the Gambit-style initial compromise point |
| `killall miglogd/syslogd`, crashlog clearing, auto-script self-deletion | Deliberate stoppage of audit logging / evidence removal | A direct real-world example of **G4** (audit log missing/stopped) |
| Pushing unauthorized sniffer configs for reconnaissance | Reconnaissance-driven configuration change | This repo's R1–R8 mostly observe host/network runtime behavior; auditing device-config changes themselves needs a separate layer (configuration management/diff monitoring) |
| Persistent reverse-shell polling via Apache mod_md | A C2-like recurring channel | Close to **R4** (messaging/C2-like channel), but since it abuses a legitimate module (ACME), detection needs to watch for deviation from normal frequency/destination rather than a signature |
| Reversibly-encrypted credentials, successfully brute-forced | A design gap in credential protection | The same root issue `netcheck`'s "exposed config/backup file" check addresses — the config file itself is a concentrated store of secrets |

## 9. Limitations

- This document organizes Unit 42's public article; no independent verification was performed.
- IOCs (IP addresses, etc.) and the YARA rule's specific byte patterns are not transcribed here, per
  this repository's existing policy (see Tables 3/4 and the YARA rule in the original article).
- The specific mechanisms behind the CVE-2024-26009/CVE-2024-26008-based impersonation and disconnection
  are Unit 42's own "medium confidence"/"could not confirm" assessments, not established fact.

## 10. References

- Unit 42, "Unit 42 Uncovers PEERSTITCH, a Stealthy FortiGate Implant," published 2026-10-14
- Related: various FortiGuard Labs PSIRT advisories (CVE-2024-47575, CVE-2025-61624, CVE-2024-26008, CVE-2024-26009)
- Related: this repository's `defense-playbook.en.md` (remedy for Gambit chain step ⑥: over-broad permissions)

> Limited to detection/defense design. No attack execution steps, weaponization, or safety-bypass techniques.
