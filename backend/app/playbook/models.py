from pydantic import BaseModel
from typing import Optional, Literal
from uuid import UUID
from datetime import datetime
from enum import Enum


class PlaybookType(str, Enum):
    BLOCK_IP         = "block_ip"
    DISABLE_ACCOUNT  = "disable_account"
    ESCALATE         = "escalate"
    ISOLATE_MACHINE  = "isolate_machine"


class PlaybookStatus(str, Enum):
    PENDING   = "pending"
    RUNNING   = "running"
    SUCCESS   = "success"
    FAILED    = "failed"
    CANCELLED = "cancelled"


# Paramètres spécifiques selon le type de playbook
class BlockIPParams(BaseModel):
    ip_address:  str
    duration_hours: Optional[int] = 24   # Durée du blocage

class DisableAccountParams(BaseModel):
    username:    str
    reason:      str

class EscalateParams(BaseModel):
    escalate_to: str            # Email ou username du destinataire
    message:     Optional[str]

class IsolateMachineParams(BaseModel):
    hostname:    str


class ExecutePlaybookRequest(BaseModel):
    alert_id:    UUID
    playbook_id: UUID
    # Un seul de ces champs sera présent selon le type de playbook
    block_ip_params:        Optional[BlockIPParams]        = None
    disable_account_params: Optional[DisableAccountParams] = None
    escalate_params:        Optional[EscalateParams]       = None
    isolate_machine_params: Optional[IsolateMachineParams] = None
    notes:       Optional[str] = None