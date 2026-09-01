from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass(frozen=True)
class PluginInfo:
    name: str
    version: str
    capabilities: frozenset[str]
    requirements: tuple[str, ...] = ()


class AndroidPlugin(ABC):
    info: PluginInfo

    @abstractmethod
    def is_available(self) -> bool:
        """Return whether this optional tool can be invoked."""

    @abstractmethod
    def get_version(self) -> str:
        """Return the installed tool version, or an unavailable marker."""

    def validate(self, target: str) -> None:
        if not target:
            raise ValueError("A target is required")

    @abstractmethod
    def execute(self, target: str) -> object:
        """Run the plugin without assuming a specific external tool."""

    @abstractmethod
    def parse(self, result: object) -> object:
        """Parse raw plugin output into a structured result."""

    def normalize(self, result: object) -> object:
        return result