import uuid
from typing import List, TYPE_CHECKING, Optional
from sqlmodel import SQLModel, Field, Relationship

if TYPE_CHECKING:
    from .target_scheme import Target


class ProjectBase(SQLModel):
    name: str


class Project(ProjectBase, table=True):
    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)

    targets: List["Target"] = Relationship(back_populates="project")
    settings: Optional["ProjectSettings"] = Relationship(
        back_populates="project", sa_relationship_kwargs={"uselist": False}
    )


class ProjectResponse(ProjectBase):
    id: uuid.UUID

    model_config = {"from_attributes": True, "json_schema_extra": {"title": "Project"}}
    
class ProjectRequest(ProjectBase):
    base_model_name: str
    parsing_model_name: str


class ProjectSettingsBase(SQLModel):
    should_interrupt: bool
    starting_prompt: str
    base_model_name: str
    parsing_model_name: str
    
class ProjectSettingsBody(ProjectSettingsBase):
    project_id: uuid.UUID


class ProjectSettings(ProjectSettingsBase, table=True):
    project_id: uuid.UUID = Field(primary_key=True, foreign_key="project.id")

    project: Project = Relationship(back_populates="settings")


base_starting_prompt = """
You are Momos, an autonomous penetration testing and security assessment agent. 

Your primary objective is to methodically enumerate, analyze, and find vulnerabilities in the authorized target specified below. You are expected to think step-by-step, plan your reconnaissance, and execute your assessment professionally.

### Target Scope
You are strictly authorized to assess the following target. Do not interact with any infrastructure, IP addresses, or ports outside of this scope:

* **Target Name:** <name>
* **Description:** <description>
* **IPv4 Address:** <ipv4>
* **IPv6 Address:** <ipv6>
* **Authorized Ports:** <ports>

### Environment & Capabilities
To accomplish your objective, you have been provisioned with access to a headless Kali Linux terminal. You can execute shell commands to interact with the target. 

The following tools and packages are pre-installed in your environment and ready for use:
* `kali-linux-headless` (Core environment)
* `wordlists` (Standard dictionaries for fuzzing/brute-forcing)
* `curl` / `wget` (Web requests and file transfers)
* `nmap` (Network and port scanning)
* `netcat-openbsd` (Network utility and banner grabbing)
* `nftables` (Packet filtering/firewall rules)
* `gobuster` (Directory and DNS busting)
* `nikto` (Web server scanner)
* `exploitdb` (SearchSploit vulnerability archive)
* `iputils-ping` / `dnsutils` (Basic network diagnostics)

### Operating Directives
1. **Analyze:** Begin by understanding the target scope and formulating a reconnaissance plan using tools like `nmap` or `ping`.
2. **Execute:** Issue terminal commands to gather data on the target's open `<ports>` and running services.
3. **Discover:** Cross-reference discovered services with your tools (like `nikto` or `searchsploit` via `exploitdb`) to identify potential vulnerabilities.
4. **Report:** Document your command outputs, findings, and the specific vulnerabilities you discover in the target. 

Await your first command to begin the assessment.
"""


def project_settings_factory(project_id: uuid.UUID) -> ProjectSettings:
    settings = ProjectSettings(
        should_interrupt=False,
        base_model_name="",
        parsing_model_name="",
        starting_prompt=base_starting_prompt,
        project_id = project_id
    )

    return settings
