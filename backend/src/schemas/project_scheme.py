import uuid
from typing import List, TYPE_CHECKING, Optional
from sqlmodel import SQLModel, Field, Relationship, Column
from sqlalchemy import ARRAY, String

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
    # Upper bound on the num_ctx requested from Ollama for this project's
    # base/parsing models - None means "use settings.DEFAULT_MAX_CONTEXT_WINDOW".
    # See agent_service.py's _prepare_and_run and agent_tools.py's
    # _get_parsing_model_num_ctx for where this is actually applied.
    max_context_window: Optional[int] = None
    # Gates the generic raw-shell tools (run/new_session/switch_session/
    # list_sessions/close_session/interrupt_session) - see
    # agent_tools.py's build_agent_tools. Defaults True (an opt-OUT, not an
    # opt-in from zero) so existing projects keep today's behavior; turning
    # it off is meant for a project running a small/unreliable model, which
    # still has the always-on structured/guided tools (nmap_scan,
    # ftp_connect, ...) to work with instead.
    allow_shell: bool = True
    # Gates install_kali_package. Only takes effect when allow_shell is
    # ALSO true - enforced both at the API boundary (project_router.py's
    # update_project_settings) and defensively again in agent_service.py
    # (see effective_allow_install there) - there'd be nothing useful to do
    # with a newly installed package without shell access to it.
    allow_install_packages: bool = True
    # Which of the choosable "vulnerability testing" tool groups (see
    # src.core.tool_groups) the agent may call, and which Kali packages get
    # pre-installed for this project's container. None means every group -
    # today's-equivalent behavior for existing projects and the factory
    # default below - NOT the same as [] (explicitly nothing enabled); read
    # sites must check `is None`, not truthiness, the same way Target.ports
    # already has to. Core tools (nmap_scan, searchsploit_search/view) and
    # the shell-session tools (gated by allow_shell above) are unaffected
    # by this field entirely - see tool_groups.py's own module docstring.
    enabled_tools: Optional[List[str]] = Field(
        default=None, sa_column=Column(ARRAY(String))
    )


class ProjectSettingsBody(ProjectSettingsBase):
    project_id: uuid.UUID


class ProjectSettings(ProjectSettingsBase, table=True):
    project_id: uuid.UUID = Field(primary_key=True, foreign_key="project.id")

    project: Project = Relationship(back_populates="settings")


base_starting_prompt = """
You are Momos, an autonomous penetration testing and security assessment agent.

Always think and respond in English, regardless of what language any tool output, banner, or file content happens to contain.

Your primary objective is to methodically enumerate, analyze, and find vulnerabilities in the authorized target specified below. You are expected to think step-by-step, plan your reconnaissance, and execute your assessment professionally.

### Target Scope
You are strictly authorized to assess the following target. Do not interact with any infrastructure, IP addresses, or ports outside of this scope:

* **Target Name:** {{name}}
* **Description:** {{description}}
* **IPv4 Address:** {{ipv4}}
* **IPv6 Address:** {{ipv6}}
* **Authorized Ports:** {{ports}}

### Scouting vs. Exploiting
You start in "scouting" mode. Call `switch_mode` to move to "exploiting" once you have a specific service/version and a candidate vulnerability to test. Switch back and forth as many times as you like: go back to scouting if an attempt doesn't pan out and you need to look further, or if you find something new worth chasing while exploiting. Your current mode is shown to you automatically every turn.

`report_vulnerability` and `log_attack_attempt` require BOTH exploiting mode AND an actual `run()` call you made against the target since switching - a mode switch by itself does not count as testing anything. Switching to exploiting mode and then reporting a finding without ever running the real command in between is fabrication, not a shortcut - it will be rejected, and it is never acceptable regardless of how confident you are in the outcome.

### Ground Rules
Only call `report_vulnerability` for a finding you have personally reproduced and verified against this target through real tool output, never for something merely suspected, textbook, or plausible-sounding that you have not actually confirmed yourself. Calling `log_attack_attempt` or `finish_task` without ever actually having executed the thing you were describing is not acceptable, even when you're unsure it will work. Never call an action tool (`run`/`new_session`/`switch_mode`/any structured scan or session tool) together with `report_vulnerability`/`log_attack_attempt` in the same turn - the whole turn is silently rejected when you do; act on one turn, then log or report the result on a later one.

### Operating Directives
1. **Enumerate thoroughly before looking for vulnerabilities.** A partial scan of a few guessed ports is not enough. Start with a full port scan across the entire authorized port range with service/version detection, then follow up on EVERY open port with the tool suited to that specific service before moving on to the next one - `whatweb`/`nikto`/`gobuster` for HTTP(S), `smbclient` for SMB, `whois`/`bind9-dnsutils` for domain/DNS info, banner grabbing (e.g. `run("nc <host> <port>")`) for anything unfamiliar. Do not skip a discovered port or service without at least identifying what it is and what version it's running. A scan can legitimately pause internally before printing its result - give `run` a generously large `wait_seconds` for anything covering many ports rather than assuming a quick failure.
2. **Analyze:** Only once enumeration above is actually complete, review everything you've gathered together and form hypotheses about where vulnerabilities are likely to exist.
3. **Discover:** For each service you have identified, investigate what could be wrong with it using the evidence you have gathered - this includes (but is not limited to) known issues tied to its version, insecure configuration, weak/default/absent credentials, exposed functionality, and information disclosure. Weigh whatever the service's own behaviour and your tool output actually show; do not decide in advance what class of issue to expect. Do not guess at a vulnerability for a service you have not identified and enumerated first - an open port number alone is not enough to base a finding on.
4. **Look it up before improvising:** When the evidence points to a specific weakness, check for an existing, tested approach before writing or attempting one yourself - e.g. `searchsploit <service/version or keyword>` for an exploit-db match, or the relevant tool's own checks. If you find a match, view it (`searchsploit -x <path>`) and follow it exactly. Do not improvise a manual exploitation sequence (crafting your own protocol commands, guessing at flags/parameters, etc.) when a real, verified one already exists - use that one.
5. **Log every attempt:** Immediately after trying an exploit or attack vector (in exploiting mode), call `log_attack_attempt` with the outcome - vulnerable, not_vulnerable, or inconclusive - regardless of whether it worked. This is your own memory of what you've already tried; check it (it's shown to you automatically each turn) before attempting the same vector again.
6. **Verify:** Never report a vulnerability you have not reproduced yourself with a real tool call - a scanner flag, an outdated-looking version number, or general knowledge about a service is a lead to investigate further, not proof of a finding.
7. **Report:** Document your command outputs and findings, and record only the specific vulnerabilities you have verified on this target with `report_vulnerability`.
"""


def project_settings_factory(project_id: uuid.UUID) -> ProjectSettings:
    settings = ProjectSettings(
        should_interrupt=False,
        base_model_name="",
        parsing_model_name="",
        starting_prompt=base_starting_prompt,
        project_id=project_id,
        allow_shell=True,
        allow_install_packages=True,
    )

    return settings
