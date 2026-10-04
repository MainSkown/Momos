from pydantic import BaseModel
from typing import Literal, Optional, Type, Union
from enum import Enum
from src.schemas import (
    OllamaDownloadProgress,
    AgentLogResponse,
    AgentRunResponse,
    KaliCreationStage,
    ResponseAttackVector,
)

# Separate registries for cleaner typing definitions
REGISTERED_INBOUND_MESSAGES: list[Type[BaseModel]] = []
REGISTERED_OUTBOUND_MESSAGES: list[Type[BaseModel]] = []

class WsTypes(str, Enum):
    WebSocketMessage = "WebSocketMessage"
    SendCommandMessage = "SendCommandMessage"
    ReceiveCommandOutputMessage = "ReceiveCommandOutputMessage"
    CreateConsoleSessionMessage = "CreateConsoleSessionMessage"
    ConsoleSessionCreatedMessage = "ConsoleSessionCreatedMessage"
    CloseConsoleSessionMessage = "CloseConsoleSessionMessage"
    ConsoleSessionClosedMessage = "ConsoleSessionClosedMessage"
    CreatedKaliUserMessage = "CreatedKaliUserMessage"
    KaliCreationStage = "KaliCreationStage"
    KaliContainerActive = "KaliContainerActive"
    ModelPullingUpdate = "ModelPullingUpdate"
    OllamaDownloadProgress = "OllamaDownloadProgress"
    AgentMessage = "AgentMessage"
    AgentInterruptRequest = "AgentInterruptRequest"
    AgentInterruptResponse = "AgentInterruptResponse"
    AgentRunStatus = "AgentRunStatus"
    AgentRunTimer = "AgentRunTimer"
    AgentContextUsage = "AgentContextUsage"
    AttackVectorUpdate = "AttackVectorUpdate"

class WebSocketMessage(BaseModel):
    type: Literal[WsTypes.WebSocketMessage]

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        
        type_annotation = cls.__annotations__.get("type")
        if type_annotation is None or WsTypes.WebSocketMessage in str(type_annotation):
            raise TypeError(
                f"Class '{cls.__name__}' must explicitly override the 'type' field"
            )
            
# --- Errors ---
class WebSocketError(BaseModel):
    code: str
    message: Optional[str]    

# --- Directional Base Classes ---

class InboundMessage(WebSocketMessage):
    type: Literal['InboundMessage']
    """Messages sent from CLIENT -> SERVER"""
    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        REGISTERED_INBOUND_MESSAGES.append(cls)

class OutboundMessage(WebSocketMessage):
    type: Literal['OutboundMessage']
    error: Optional[WebSocketError] = None
    
    """Messages sent from SERVER -> CLIENT"""
    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        REGISTERED_OUTBOUND_MESSAGES.append(cls)

# --- Inbound Subclasses (Client Sends) ---

class SendCommandMessage(InboundMessage):
    project_id: str
    type: Literal[WsTypes.SendCommandMessage]
    command: str
    # Which console session to run this in - the session's own user
    # (root/momos) was already fixed when it was created
    # (CreateConsoleSessionMessage), so it's not re-sent per command.
    session: str

class CreateConsoleSessionMessage(InboundMessage):
    project_id: str
    type: Literal[WsTypes.CreateConsoleSessionMessage]
    user: Literal["root", "momos"]

class CloseConsoleSessionMessage(InboundMessage):
    project_id: str
    type: Literal[WsTypes.CloseConsoleSessionMessage]
    session: str

class AgentInterruptResponseMessage(InboundMessage):
    project_id: str
    target_id: str
    type: Literal[WsTypes.AgentInterruptResponse]
    approved: bool
    # Additive, optional - Single Agent mode's existing clients never send
    # this (its one interrupt is already fully identified by target_id
    # alone) and keep working unchanged. A Multi Agent client that knows
    # which sub-run it's answering (see AgentInterruptRequest.agent_run_id
    # below) should set it - agent_service.py's _on_interrupt_response
    # resolves by it directly when present, skipping the best-effort
    # "first pending interrupt under this target" fallback it still falls
    # back to otherwise.
    agent_run_id: Optional[str] = None

# --- Outbound Subclasses (Server Sends) ---

class ReceiveCommandOutputMessage(OutboundMessage):
    project_id: str
    type: Literal[WsTypes.ReceiveCommandOutputMessage]
    output: str
    session: str

class ConsoleSessionCreatedMessage(OutboundMessage):
    project_id: str
    type: Literal[WsTypes.ConsoleSessionCreatedMessage]
    session: str
    user: Literal["root", "momos"]

class ConsoleSessionClosedMessage(OutboundMessage):
    project_id: str
    type: Literal[WsTypes.ConsoleSessionClosedMessage]
    session: str

class CreatedKaliUserMessage(OutboundMessage):
    project_id: str
    type: Literal[WsTypes.CreatedKaliUserMessage]
    client_id: str

class KaliCreationStageMessage(OutboundMessage):
    project_id: str
    type: Literal[WsTypes.KaliCreationStage]
    stage: KaliCreationStage

class KaliContainerActiveMessage(OutboundMessage):
    """Broadcast once a Kali container actually becomes active for a
    project - unlike CreatedKaliUserMessage (only sent for the explicit
    "connect" flow in kali_user.py), this fires from KaliRegistry's own
    get_manager, the single chokepoint every trigger (an agent run, a
    console connect, or any Kali-using tool) goes through."""
    project_id: str
    type: Literal[WsTypes.KaliContainerActive]

class ModelPullingUpdate(OutboundMessage):
    type: Literal[WsTypes.ModelPullingUpdate]
    progress: OllamaDownloadProgress

class AgentMessage(OutboundMessage):
    type: Literal[WsTypes.AgentMessage]
    log: AgentLogResponse

class AgentInterruptRequest(OutboundMessage):
    project_id: str
    target_id: str
    type: Literal[WsTypes.AgentInterruptRequest]
    tool_calls: list[dict]
    # Additive, optional - set to the real sub-run agent_run_id that
    # raised this interrupt for Multi Agent mode (see
    # orchestrator_tools.py's _drain_sub_agent) or to target_id itself for
    # Single Agent mode (where agent_run_id always equals target_id - see
    # Agent.__init__'s own comment). A client that echoes this straight
    # back on AgentInterruptResponseMessage.agent_run_id resolves
    # unambiguously; one that doesn't still works via
    # AgentService.get_pending_interrupt/_on_interrupt_response's own
    # best-effort "first pending interrupt under this target" fallback.
    agent_run_id: Optional[str] = None

class AgentRunStatus(OutboundMessage):
    project_id: str
    target_id: str
    type: Literal[WsTypes.AgentRunStatus]
    running: bool

class AgentRunTimer(OutboundMessage):
    type: Literal[WsTypes.AgentRunTimer]
    run: AgentRunResponse

class AgentContextUsage(OutboundMessage):
    project_id: str
    target_id: str
    type: Literal[WsTypes.AgentContextUsage]
    used_tokens: int
    context_window: int
    # Every current call site (Single Agent mode's own run, the
    # orchestrator's own run, and _drain_sub_agent for every sub-agent it
    # spawns) sets both. Optional/defaulted only so this stays wire-
    # compatible with any older client still expecting the shape from
    # before multi_agent made more than one run per target possible.
    agent_run_id: Optional[str] = None
    role: Optional[str] = None

class AttackVectorUpdate(OutboundMessage):
    """Pushed on every AttackVector create/update (see
    run_registry.broadcast_attack_vector) - the board's live Kanban view
    (Phase 7) applies this directly instead of polling the
    .../attack_vectors endpoint, which is only needed for the initial
    load."""
    project_id: str
    target_id: str
    type: Literal[WsTypes.AttackVectorUpdate]
    vector: ResponseAttackVector

# --- Union Typings ---
#! Must be at the end of this file - filled on run
InboundTrafficUnion = Union[*REGISTERED_INBOUND_MESSAGES]
OutboundTrafficUnion = Union[*REGISTERED_OUTBOUND_MESSAGES]