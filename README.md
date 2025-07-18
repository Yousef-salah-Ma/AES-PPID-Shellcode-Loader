# AES Encrypted Shellcode Loader with PPID Spoofing

This is a fully functional Red Team shellcode loader written in C for Windows. It performs:

- **AES-CBC decryption** of encrypted shellcode using the Windows CNG API (`bcrypt`).
- **Process injection** via `VirtualAllocEx` and `CreateRemoteThread`.
- **PPID spoofing** using `STARTUPINFOEXA` and `UpdateProcThreadAttribute`.
- Target parent process is dynamically selected (e.g., `explorer.exe`).

> ⚠️ For educational and research purposes only.

---

## 🛠 Features

- ✅ AES-CBC 256-bit shellcode decryption (BCrypt API)
- ✅ Remote process injection
- ✅ Parent PID spoofing (PPID) with explorer.exe
- ✅ Full Windows API usage (no external libraries)

---

## 🧠 Technical Overview

1. **Decryption**  
   The shellcode is encrypted with AES-256 in CBC mode. The `SimpleDecryption` wrapper handles the decryption using `BCryptDecrypt`.

2. **Parent PID Spoofing**  
   The target process (`notepad.exe`) is launched with `explorer.exe` as its spoofed parent using the attribute list trick with `CreateProcessA`.

3. **Shellcode Injection**  
   After decryption, the shellcode is written into the remote process and executed via `CreateRemoteThread`.

---

## 🖥 Usage

Compile with:
```bash
cl loader.c /link bcrypt.lib advapi32.lib
