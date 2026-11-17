# Chrome App-Bound Encryption Research

**Malware Development · Windows Internals · Browser Security · Nim**

A hands-on MalDev research project investigating Google Chrome credential storage, Windows DPAPI, Chrome App-Bound Encryption (ABE), and Windows-native programming with Nim. The work was carried out in an isolated Windows 11 lab using synthetic test credentials and a Kali Linux HTTP server.

> **Research and responsible-use notice**
>
> This repository documents a controlled security experiment performed on systems and accounts under my control. It is intended for authorized security research and education. Do not use the code on systems or accounts without explicit permission. The experiment does not establish a new zero-day vulnerability or a universal/direct bypass of Chrome App-Bound Encryption.

## Inspiration and attribution

The project began with inspiration from **[OffensiveNim](https://github.com/byt3bl33d3r/OffensiveNim)** by **byt3bl33d3r**, which demonstrates the use of Nim in offensive security and Windows development.

My subsequent work involved investigating Chrome profile storage, developing and debugging a two-component Nim lab workflow, integrating Windows APIs and SQLite, and evaluating the differences between the program's state reporting and independently collected evidence. Credit for OffensiveNim belongs to its original author; this repository documents my own follow-on research and experiments.

## Research goals

- Understand the differences between Chrome's legacy `v10` protected-data format and newer `v20` App-Bound Encryption.
- Explore Windows DPAPI, AES-GCM, process tokens, native API interoperability, and Chrome profile storage.
- Investigate how browser policy and account/profile state relate to encryption-format observations.
- Record what the program reports and distinguish that from what was independently verified in the lab.

## Source files

| File | Role |
| --- | --- |
| `preparer.nim` | Lab orchestrator: Windows environment and privilege-context inspection, Chrome state checks, and coordination of the second executable. |
| `chromecreds.nim` | Browser-data research component: Chrome profile discovery, SQLite database access, legacy-format cryptography, and laboratory result handling. |

The programs are **separately compiled Windows executables**, not two Nim modules imported into one process. In the tested design, the second executable was supplied by the lab HTTP server and executed locally under a different filename. The preparer does **not** perform process injection of this second executable. Separate DLL/IElevator research attempts took place earlier in the investigation and should not be confused with the final two-executable workflow.

### Laboratory component relationships

```text
Windows 11 test VM                         Kali Linux lab server
------------------                         ---------------------
Nim orchestrator                            Research artifact source
       |                                              |
       |            receives second binary             |
       |<---------------------------------------------+
       |
Local copy of second component
       |
       |  one conditional execution
       v
Browser-data research component
       |
       v
Local test-output artifact
       |
       |             HTTP lab output
       +---------------------------------------------> Results receiver
                                                     HTTP 200 observed
```

This diagram summarizes component responsibilities, not every possible conditional code path. Different branches in the orchestrator may exit or report an unconfirmed state.

## Technology stack

| Area | Technology |
| --- | --- |
| Language | Nim |
| Windows interoperability | Winim, Win32 APIs |
| Protected-data research | Windows DPAPI, `nimcrypto` / AES-GCM |
| Browser metadata | JSON, Chrome `Local State` |
| Data storage | SQLite, `tiny_sqlite`, `sqlite3.c` |
| Laboratory platform | Windows 11 VM, Chrome, Kali Linux |
| Network observation | HTTP laboratory server |

## Prerequisites

- A **Windows** development or laboratory environment, with Nim and Nimble installed.
- A compatible C toolchain for the installed Nim version.
- Required Nim dependencies: `winim`, `nimcrypto`, and `tiny_sqlite`.
- The compatible `sqlite3.c` source required by the `{.compile: "sqlite3.c".}` directive in `chromecreds2.nim`.
- A controlled test environment and synthetic accounts/data; do not use real user credentials.

Dependency versions and compiler/toolchain compatibility should be validated against the exact environment used for a build; they are not pinned in the source files documented here.

## Compilation

The two programs are built **separately**. Insert the exact build commands used for the corresponding files below.

### 1. Orchestrator — `preparer.nim`

```powershell
nim c -d:release preparer.nim
```

### 2. Browser-data component — `chromecreds.nim`

```powershell
nim c -d:release --dynlibOverride:sqlite3 chromecreds.nim
```

**Note:** Previous exploratory DLL experiments used a *different* source file and build mode. Their command is not interchangeable with the command for `chromecreds2.nim` and is intentionally not listed as part of the final two-file build.

## Lab baseline — November 17, 2026

| Item | Observed state |
| --- | --- |
| Operating system | Windows 11 Home 25H2 (build 26200.9711) |
| Chrome | 157.0.8103.79 |
| Profile under test | Profile 3 |
| Initial interactive process | Medium-integrity / non-elevated |
| Chrome ABE policy | `ApplicationBoundEncryptionEnabled = 1`, shown as `true` / `OK` in Chrome |
| Microsoft Defender | Real-time protection enabled; no exclusions reported |
| Test records | Three synthetic entries |
| Initial encrypted-record prefix | All three began with hex `763230` (ASCII `v20`) |

## Experiment and interpretation

The Windows lab captured the coordinator's messages and the subsequent test activity. On the receiving side, the Kali HTTP server logged a successful request (`HTTP 200`), and the laboratory output contained three readable test records.

**Evidence boundary:** The source's `detectVersion()` logic uses Chrome metadata and Registry policy to classify the environment. Under some conditions it reports `v10` based on policy state **without inspecting the encrypted prefix of each stored database row**. Therefore, a later program-reported `v10` status is **not independent evidence** that all prior `v20` records were converted. The documented baseline independently confirms the **initial** `v20` prefixes; an equivalent post-execution prefix measurement was not established in this investigation.

Earlier attempts to investigate direct `v20` decryption using IElevator/COM and process-context experiments did **not** result in a verified, working direct `v20` decryptor.

## Development notes and lessons learned

- **Profile discovery:** Supporting `Default` and `Profile*` directories avoids assuming one fixed Chrome profile.
- **Database selection:** The current `getChromePaths()` implementation prefers `Login Data For Account`; because it uses `elif`, it does not process both databases when both exist in a single profile.
- **Windows paths:** Switching to `getEnv("LOCALAPPDATA")` addressed a path-handling issue encountered during development.
- **JSON integrity:** An earlier serialization approach disrupted profile data; the final source uses a different representation and creates a backup before writing preferences.
- **Native API checks:** Some API return values are not validated, making a reported action weaker evidence than an independently verified outcome.
- **Experiment design:** Configuration, encrypted-record format, and reported success are three different things; they should be measured and documented separately.

## Portfolio write-up

For the project narrative, screenshots, technical analysis, lab output, and redacted demonstration, see:

**[Chrome App-Bound Encryption Research — Portfolio](https://bigsha.pages.dev/projects/chrome-abe/)**

## Author

**Nehoray Shaul** — Offensive Security / Malware Development Research

Portfolio: https://bigsha.pages.dev/

## Acknowledgment

Thanks to **byt3bl33d3r** for publishing [OffensiveNim](https://github.com/byt3bl33d3r/OffensiveNim), the original inspiration for this work.
