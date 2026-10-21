# opscope

> **Fast, standalone x86/x64 Opcode Inspector & Stream Disassembler**  
> Written in Rust using `iced-x86`. Completely offline, zero external runtime dependencies, no server or network required.

`opscope` is a command-line tool designed for reverse engineers, malware analysts, and low-level developers. It parses raw binary payloads, dumps, and shellcode into readable Intel-syntax assembly with colored syntax highlighting, control flow direction markers, and execution statistics.

---

## ✨ Features

- **Blazing Fast Decoding**: Powered by `iced-x86`, decoding thousands of instructions per second.
- **Multiple Input Sources**:
  - Raw binary files (`.bin`, `.raw`, shellcode dumps, `.text` section extracts).
  - Inline hex strings via `--hex "48 31 c0 ..."` (supports spaces, `0x`, `\x`).
  - Standard input pipe (`cat payload.bin | opscope -`).
- **Syntax Highlighting (ANSI)**:
  - Registers (Green)
  - Mnemonics & Prefixes (Yellow & Bold)
  - Memory offsets & Immediate values (Cyan)
  - Jump/Call targets (Red / Magenta)
- **Control Flow Tracing**:
  - `↓ jmp` / `↓ jcc`: Forward branch.
  - `↑ loop`: Backward loop branch.
  - `● CALL`: Subroutine invocation.
  - `■ RET`: Function return.
  - `>LOC<`: Jump target location label.
- **Architecture Switching**: Supports 64-bit (default) and 32-bit (`--32`).
- **Telemetry & Summary**: Displays total decoded instructions, branching frequency, and top mnemonics.

---

## 🚀 Quick Start

### 1. Disassemble inline hex string:
```bash
opscope --hex "48 31 c0 48 ff c0 75 fb e8 00 00 00 00 c3"
```

### 2. Disassemble a raw binary file:
```bash
opscope shellcode.bin
```

### 3. Specify custom RIP base address:
```bash
opscope --rip 0x401000 --hex "31 c0 ff c0 75 fb c3"
```

### 4. 32-bit x86 mode:
```bash
opscope --32 legacy.bin
```

---

## 🛠️ Command-Line Options

| Flag | Description | Default |
|------|-------------|---------|
| `--hex <STR>` | Disassemble raw hex string | None |
| `--rip <ADDR>` | Custom instruction pointer / base offset | `0x10000000` |
| `--32` | Disassemble as 32-bit x86 | 64-bit |
| `--64` | Disassemble as 64-bit x86_64 | 64-bit |
| `--no-flow` | Hide branch/loop markers (`↓`, `↑`, `CALL`) | Disabled |
| `--no-stats` | Hide execution & statistics summary | Disabled |
| `-h, --help` | Display help screen | - |

---

## 📦 Building from Source

Requires Rust 1.70+:

```bash
cargo build --release
```

The resulting binary will be in `target/release/opscope.exe`.

---

## 📁 Release Artifacts

Pre-built binaries and source code archives are available in the [`releases/`](./releases/) directory:
- `releases/opscope.exe` — Standalone Windows 64-bit executable.
- `releases/source_code.zip` — Compressed source bundle.
