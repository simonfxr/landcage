# PSEC schema provenance

`ProcessSecurityEnvironment.fbs` is an unmodified copy from Microsoft's
[mxc](https://github.com/microsoft/mxc), commit
`40df784b2c32e764eaed51899a10ee936a2d7c0c`,
`external/windows-sdk/ProcessSecurityEnvironment.fbs`. Its Microsoft MIT license
is included in `LICENSE`. The generated Go bindings derive from that schema.

Regenerate from the repository root with FlatBuffers `flatc` 25.12.19:

```sh
flatc --go --gen-onefile --go-namespace layout \
  -o internal/winpsec/internal/layout \
  internal/winpsec/schema/ProcessSecurityEnvironment.fbs
```

The source schema includes 1.1 fields; this encoder deliberately emits only
version 1.0. The API signatures, zero create flags, optional version-export
behavior, and `PSE_SUPPORT_FS_DENY = 1` follow the same commit's
`src/mxc-sdk/src/backends/process_container/common/secenv.rs`.
`base_container_helpers.rs` supplies the `internetClient` capability for permitted
egress. No learning-mode capability is emitted.

`NetworkDeny` emits explicit deny-by-default egress and no network capabilities.
`NetworkAllowEgress` emits allow-by-default egress and `internetClient`, not
unrestricted host networking. Neither emits a 1.1 ingress table or grants
private-network server/host-loopback capabilities.

Policies keep Win32k enabled for USER32-dependent runtimes and encode all ten
separate job UI restriction bits (`0x03ff`), matching the reference encoder's
fully restricted `EffectiveUiRestrictions` mask in `common/job_object.rs`.

## Integration requirements

`Create` accepts an `Encode` result and checks baseline version support (when the
optional version export exists), the required exports, and native deny-path
capability before creation. Query failures and unsupported capabilities are
fatal. The Windows API validates the complete FlatBuffer; the local requirement
inspection is not a general FlatBuffers verifier.

Creation alone does not sandbox a process. Launch must attach the borrowed
environment handle using `PROC_THREAD_ATTRIBUTE_SECURITY_ENVIRONMENT`
(`35 | 0x00020000`) in a `STARTUPINFOEXW` attribute list. Pass a **pointer to the
handle value**, with `sizeof(HANDLE)` bytes, to `UpdateProcThreadAttribute`;
keep that storage alive through `CreateProcessW`, use
`EXTENDED_STARTUPINFO_PRESENT`, and set `StartupInfo.cb = sizeof(STARTUPINFOEXW)`.
Keep the environment open until contained children exit; close it with
`CloseProcessSecurityEnvironment`, never `CloseHandle`.

The schema binding does not launch processes; `process_windows.go` implements
the native launcher. No fallback backend, ACL changes, or learning mode is used.
Cross-compilation and encoder unit tests do not validate Windows enforcement.
