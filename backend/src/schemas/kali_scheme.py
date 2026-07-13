from pydantic import BaseModel

class KaliUser(BaseModel):
    client_id: str