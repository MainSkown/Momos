from langchain_core import tool 

@tool
def execute_kali_command(command: str) -> str:
    """Executes a command in the Kali Linux container. Use this to interact with the environment. Note that every command is executed in different session."""
    
    return ""

agent_tools = [execute_kali_command]