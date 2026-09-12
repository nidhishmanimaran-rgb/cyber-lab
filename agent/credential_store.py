"""Protected credential storage for the Windows managed-device agent."""

from __future__ import annotations

import ctypes
import os
from ctypes import wintypes
from pathlib import Path
from typing import Protocol


class SecretStoreError(RuntimeError):
    pass


class SecretStore(Protocol):
    def load(self) -> str | None: ...
    def save(self, value: str) -> None: ...
    def delete(self) -> None: ...


class WindowsDpapiStore:
    """Encrypt one agent credential with the current Windows user DPAPI key."""

    class _Blob(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_ubyte))]

    def __init__(self, path: Path):
        if os.name != "nt":
            raise SecretStoreError("Windows DPAPI storage is only available on Windows.")
        self.path = path

    @staticmethod
    def _protect(raw: bytes) -> bytes:
        crypt32 = ctypes.windll.crypt32
        kernel32 = ctypes.windll.kernel32
        source = ctypes.create_string_buffer(raw)
        source_blob = WindowsDpapiStore._Blob(len(raw), ctypes.cast(source, ctypes.POINTER(ctypes.c_ubyte)))
        output_blob = WindowsDpapiStore._Blob()
        if not crypt32.CryptProtectData(ctypes.byref(source_blob), None, None, None, None, 0, ctypes.byref(output_blob)):
            raise SecretStoreError("Windows credential protection failed.")
        try:
            return ctypes.string_at(output_blob.pbData, output_blob.cbData)
        finally:
            kernel32.LocalFree(output_blob.pbData)

    @staticmethod
    def _unprotect(encrypted: bytes) -> bytes:
        crypt32 = ctypes.windll.crypt32
        kernel32 = ctypes.windll.kernel32
        source = ctypes.create_string_buffer(encrypted)
        source_blob = WindowsDpapiStore._Blob(len(encrypted), ctypes.cast(source, ctypes.POINTER(ctypes.c_ubyte)))
        output_blob = WindowsDpapiStore._Blob()
        if not crypt32.CryptUnprotectData(ctypes.byref(source_blob), None, None, None, None, 0, ctypes.byref(output_blob)):
            raise SecretStoreError("Windows credential decryption failed.")
        try:
            return ctypes.string_at(output_blob.pbData, output_blob.cbData)
        finally:
            kernel32.LocalFree(output_blob.pbData)

    def load(self) -> str | None:
        if not self.path.exists():
            return None
        try:
            return self._unprotect(self.path.read_bytes()).decode("utf-8")
        except (OSError, UnicodeDecodeError, SecretStoreError) as exc:
            raise SecretStoreError("Unable to load the protected agent credential.") from exc

    def save(self, value: str) -> None:
        if not value:
            raise SecretStoreError("Cannot store an empty credential.")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        encrypted = self._protect(value.encode("utf-8"))
        temporary = self.path.with_suffix(self.path.suffix + ".tmp")
        temporary.write_bytes(encrypted)
        os.replace(temporary, self.path)

    def delete(self) -> None:
        try:
            self.path.unlink()
        except FileNotFoundError:
            return


def default_secret_store(state_dir: Path) -> SecretStore:
    return WindowsDpapiStore(state_dir / "agent-token.dpapi")
