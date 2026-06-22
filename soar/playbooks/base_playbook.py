"""playbooks/base_playbook.py — Classe abstraite"""
from abc import ABC, abstractmethod
class BasePlaybook(ABC):
    @abstractmethod
    async def execute(self, alert: dict) -> dict: ...
