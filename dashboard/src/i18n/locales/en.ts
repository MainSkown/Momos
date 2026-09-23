export const en = {
    tools: {
        tools: 'TOOLS',
        overview: 'Overview',
        vulnerabilities: 'Vulnerabilities',
        project_settings: 'Project Configuration',
        config_summary: 'Project Config Summary',
        model: 'Model',
        kali_instance: 'Kali Instance',
        active: 'active',
        connecting: 'connecting',
        inactive: 'inactive'
    },
    context_window: {
        context_window: "CONTEXT WINDOW"
    },
    targets:{
        targets: 'Targets',
        target: "Target",
        no_target: "Target is not defined",
        enter_name: "Enter target's name",
        name_empty: "Name can not be empty",
        name: 'Name',
        ipv4: 'IPv4',
        ipv6: 'IPv6',
        domain: 'Domain',
        description: 'Description',
        ports: 'Ports',
        no_targets: 'No targets',
        no_ipv4: "Enter target's IPv4",
        no_ipv6: "Enter target's IPv6",
        no_domain: "Enter target's domain",
        no_ports: "Enter target's ports",
        to_delete: "Are you sure you want to delete this target?",
        delete_info: "This action cannot be undone.",
        scan_duration: "Enter scan duration",
        duration_required: "To start work first define task duration in settings",
        agent_wants_to_run: "Agent wants to run the following",
        agent_start_failed: "Could not start the agent",
        agent_pause_failed: "Could not pause the agent",
        agent_finish_failed: "Could not finish the agent",
        hold_to_finish_tooltip: "Click to pause, hold to finish the run",
        hold_to_finish_tooltip_paused: "Click to resume, hold to finish the run"
    },

    notify: {
        address_already_exist: 'There is already a target with given address',
        address_empty: 'Address can not be empty',
        invalid_addr: 'Invalid address. It should be: IPv4, IPv6 or a domain address',
        name_empty: 'Name can not be empty',
        agent_model_required: 'Agent model must be selected',
        parsing_model_required: 'Parsing model must be selected',
        agent_model_not_downloaded: 'Agent model must be downloaded first',
        parsing_model_not_downloaded: 'Parsing model must be downloaded first',
        could_not_create_project: 'Could not create project',
        model_download_failed: 'Failed to download model "{name}"',
        model_downloading: 'Downloading "{name}" in the background...',
        model_downloaded: '"{name}" downloaded and selected',
        project_settings_saved: 'Project settings saved',
        project_settings_save_failed: 'Could not save project settings',
        project_deleted: 'Project deleted',
        project_delete_failed: 'Could not delete project'
    },

    project: {
        name: "Project's name",
        create_new: "Create new project",
        no_projects: "There are no projects yet",
        enter_name: "Enter project's name",
        delete: "Delete Project",
        delete_confirm: "Are you sure you want to delete this project?",
        deleting: "Deleting...",
        save_settings: "Save Settings",
        saving: "Saving...",
        placeholder_name: "Target's name",
        placeholder_description: "Target's description",
        placeholder_ipv4: "Target's IPv4 address",
        placeholder_ipv6: "Target's IPv6 address",
        placeholder_ports: "Target's authorized ports"
    },

    models: {
        recommended_agent: "Recommended agent models",
        recommended_parsing: "Recommended parsing models",
        show_installed: "Show installed models",
        hide_installed: "Hide installed models",
        installed: "Installed",
        select_model: "Select a model",
        none_selected: "None selected",
        select_base_model: "Select Base Model",
        select_parsing_model: "Select Parsing Model",
        base_model: "Base Model",
        parsing_model: "Parsing Model",
        not_installed_title: "Model not installed",
        not_installed_body: '"{name}" is not installed. Download it now and use it once ready?',
        install: "Install model",
        delete: "Delete model",
        deleted: "Deleted",
        parameters: "Parameters",
        size: "Size",
        context_window: "Context window",
        thinking: "Thinking"
    },

    settings: {
        settings: "Settings",
        ai: "AI",
        user_options: "User Options",
        should_interrupt: "Should Interrupt",
        enable_interruption: "Enable interruption handling",
        allow_shell: "Allow Shell",
        enable_allow_shell: "Allow raw terminal commands (run/new_session/...)",
        allow_install_packages: "Allow Installing Packages",
        enable_allow_install_packages: "Allow installing new Kali packages (requires Allow Shell)",
        starting_prompt: "Starting Prompt",
        available_placeholders: "Available placeholders"
    },

    console: {
        user_console: "User Console",
        root: "Root",
        momos: "Momos",
        session_initialized: "Session initialized. Select privileges above.",
        connecting: "Connecting to client...",
        checking_session: "Checking for active session",
        no_active_session: "No active session",
        connect_to_kali: "Connect to Kali",
        connect_failed: "Could not connect to Kali",
        stage: {
            checking_container: "Checking for existing container",
            starting_container: "Starting Kali container",
            updating_packages: "Updating package lists",
            installing_packages: "Installing Kali packages",
            creating_user: "Setting up user account",
            verifying_setup: "Verifying container setup"
        }
    },

    overview: {
        summary: "Summary",
        agent_logs: "Agent Logs"
    },

    agent_logs: {
        tool_install_package: "Package Installed",
        tool_run: "Terminal",
        tool_new_session: "Session Opened",
        tool_switch_session: "Session Switched",
        tool_close_session: "Session Closed",
        tool_list_sessions: "Listed Sessions",
        tool_interrupt_session: "Session Interrupted",
        tool_switch_mode: "Mode Switched",
        tool_report_vulnerability: "Vulnerability Report",
        tool_log_attack_attempt: "Attack Attempt Logged",
        tool_finish_task: "Task Finished",
        running: "Agent is running",
        no_logs: "No agent activity yet"
    },

    vulnerabilities: {
        title: "Vulnerabilities",
        no_vulnerabilities: "No vulnerabilities were found yet",
        name: "Name",
        severity: "Severity",
        vector: "CVSS Vector",
        no_vector: "No CVSS vector",
        poc: "Proof of Concept",
        found_in: "Target",
        found_by: "Model",
        unknown_model: "Unknown model",
        edit: "Edit vulnerability",
        save: "Save",
        cancel: "Cancel",
        save_success: "Vulnerability updated",
        save_failed: "Could not update vulnerability",
        to_delete: "Are you sure you want to delete this vulnerability?",
        delete_info: "This action cannot be undone.",
        delete_success: "Vulnerability deleted",
        delete_failed: "Could not delete vulnerability",
        severity_informational: "Informational",
        severity_low: "Low",
        severity_medium: "Medium",
        severity_high: "High",
        severity_critical: "Critical",
        severity_locked_by_vector: "Locked - derived from the CVSS vector (score: {score})",
        filter_name: "Filter by name...",
        filter_target: "Target",
        filter_model: "Model",
        filter_all_targets: "All targets",
        filter_all_models: "All models",
        filter_date_from: "From",
        filter_date_to: "To"
    },

    universal:{
        yes: "Yes",
        no: "No",
        add: "Add",
    },

    time:{
        "hours_minutes": "{hours}h {minutes}m"
    }
}
