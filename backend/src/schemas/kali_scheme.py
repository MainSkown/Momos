from pydantic import BaseModel
from typing import Optional

class KaliUser(BaseModel):
    client_id: str
    pending: Optional[bool] = None