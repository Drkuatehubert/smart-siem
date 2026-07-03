from datetime import datetime

from pydantic import BaseModel


class AgentOut(BaseModel):
    id: str
    host: str
    os: str
    status: str
    last_seen: datetime
