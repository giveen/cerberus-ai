from __future__ import annotations


class Prompt:
    @staticmethod
    def ask(prompt: str, default: str | None = None, password: bool = False) -> str:
        _ = password
        response = input(f"{prompt}: ")
        return response if response else (default or "")


class Confirm:
    @staticmethod
    def ask(prompt: str, default: bool = False) -> bool:
        response = input(f"{prompt} [{'Y/n' if default else 'y/N'}]: ").strip().lower()
        if not response:
            return default
        return response in {"y", "yes", "true", "1"}