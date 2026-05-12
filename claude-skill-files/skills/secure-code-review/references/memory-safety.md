# Memory Safety

Memory safety vulnerabilities — buffer overflows, use-after-free, integer overflows,
format string bugs — are the root cause of a large proportion of critical CVEs in
systems software. In languages with automatic memory management (C#, Go, Python, JS)
these are largely eliminated by the runtime. In Rust they are eliminated by the
compiler except inside `unsafe` blocks. In C and C++ they require constant vigilance.

This file focuses on Rust `unsafe` blocks (your primary exposure) and general
principles that apply when auditing any low-level code.

Load `references/lang/rust.md` for Rust-specific patterns.
Load `references/lang/csharp.md` for C# `unsafe` / `Span<T>` / P/Invoke patterns.

---

## Rust: unsafe Blocks

Rust's safety guarantees hold everywhere except inside `unsafe` blocks. Each `unsafe`
block is a contract: the programmer asserts that the invariants the compiler cannot
verify are upheld. Violations cause undefined behaviour — the same class of bug as
C/C++ memory corruption.

### What unsafe Permits (and What Can Go Wrong)

| Operation | Risk |
|-----------|------|
| Dereferencing raw pointers | Null dereference, dangling pointer, use-after-free |
| Calling unsafe functions (FFI, intrinsics) | Any C-style memory bug |
| Accessing/modifying mutable static | Data races in multithreaded code |
| Implementing unsafe traits | Unsound trait impl breaks downstream safe code |
| Accessing union fields | Wrong field interpretation, undefined behaviour |

### Auditing unsafe Blocks

For every `unsafe` block in code that processes untrusted input:

1. **Is the block necessary?** Many `unsafe` blocks exist for performance or
   convenience and can be replaced with safe equivalents. If it can be removed, remove it.

2. **Is the safety invariant documented?** There should be a comment immediately above
   the block explaining what invariant is being upheld and why it holds.
   ```rust
   // SAFETY: `ptr` is non-null and valid for `len` bytes because it was
   // obtained from `Vec::as_ptr()` on a live Vec with capacity >= len.
   unsafe { std::slice::from_raw_parts(ptr, len) }
   ```
   An `unsafe` block without a `// SAFETY:` comment is a red flag.

3. **Are the preconditions checked before the block?** Length checks, null checks,
   alignment checks, lifetime assertions.

4. **Is user-controlled data used in pointer arithmetic or slice indices?**
   Integer overflow before indexing is a common bug:
   ```rust
   // DANGEROUS — offset may overflow before the bounds check
   let end = start + user_len;   // overflows if user_len is near usize::MAX
   &buf[start..end]              // may panic or wrap to wrong range

   // SAFE — checked arithmetic
   let end = start.checked_add(user_len)
       .filter(|&e| e <= buf.len())
       .ok_or(Error::InvalidLength)?;
   ```

5. **Is there a safe abstraction available?** `std::slice`, `bytemuck`, `zerocopy`,
   `memoffset` — prefer these over raw pointer arithmetic.

### FFI (Calling C from Rust)

Every FFI call is `unsafe`. Additional concerns:

- Validate all values passed to C functions; C does not check bounds
- Ensure strings are null-terminated (`CString`, `CStr`) before passing to C
- Never pass Rust references across FFI unless the ABI is explicitly designed for it
- Handle C error codes — they are not propagated automatically
- Check ownership: who is responsible for freeing memory allocated by C?

---

## C# unsafe and Interop

C# with `unsafe` keyword or P/Invoke introduces the same class of bugs as C:

```csharp
// unsafe block — same risks as C
unsafe {
    int* ptr = &value;
    // pointer arithmetic here bypasses .NET safety
}

// P/Invoke — calling unmanaged code
[DllImport("native.dll")]
static extern int ProcessBuffer(byte[] buffer, int length);
// Risk: length must accurately reflect buffer.Length; C does not check
```

**Rules for C# unsafe / P/Invoke:**
- Keep `unsafe` blocks minimal — extract to a small, well-tested method
- Verify buffer lengths explicitly before every P/Invoke call
- Use `Span<T>` and `Memory<T>` instead of raw pointers where possible
- Use `Marshal.AllocHGlobal` / `Marshal.FreeHGlobal` in matched pairs; prefer
  `SafeHandle` to ensure cleanup on exceptions

---

## Integer Overflow and Underflow

Integer overflow is the gateway to buffer overflows in many vulnerability chains.
A calculated size overflows to a small number, a too-small buffer is allocated,
and subsequent writes overflow it.

**Pattern to audit:**

```
user_count * ITEM_SIZE     → multiply before checking: overflow
offset + user_length       → addition before bounds check: overflow
(size_t)(signed_value)     → sign extension: negative becomes huge positive
```

**Safe patterns:**
- Use checked arithmetic (`checked_add`, `checked_mul`, `saturating_*`) before
  using a computed value as an allocation size or index
- Validate that user-supplied sizes are within expected bounds before any arithmetic
- In C#: enable `checked` context for arithmetic on user-supplied values

---

## Tools

```bash
# Rust
cargo audit                          # CVEs in dependencies
cargo clippy -- -D warnings          # static analysis including some safety lints
cargo +nightly miri test             # undefined behaviour detector (slow; for critical code)
RUSTFLAGS="-Z sanitizer=address" cargo test  # AddressSanitizer

# C# / .NET unsafe code
dotnet-asan (preview)                # AddressSanitizer integration
PVS-Studio, Coverity                 # static analysis for unsafe/interop paths

# General
valgrind --memcheck ./binary         # Linux: memory error detection for native code
```

---

## Memory Safety Review Checklist

- [ ] Every `unsafe` block has a `// SAFETY:` comment documenting the invariant
- [ ] User-controlled values used in pointer arithmetic checked for overflow before use
- [ ] User-controlled buffer lengths validated against actual buffer size before use
- [ ] FFI calls validate all inputs before passing to C functions
- [ ] P/Invoke buffer length parameters match actual buffer lengths
- [ ] No raw `malloc`/`free` pairs — use RAII or `SafeHandle` to ensure cleanup
- [ ] `cargo audit` / `cargo clippy` clean
- [ ] `unsafe` blocks minimized — refactored to safe abstractions where possible
