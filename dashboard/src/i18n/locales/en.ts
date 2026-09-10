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
        duration_required: "To start work first define task duration in settings"
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
        model_downloaded: '"{name}" downloaded and selected'
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
        starting_prompt: "Starting Prompt",
        available_placeholders: "Available placeholders"
    },

    console: {
        user_console: "User Console",
        root: "Root",
        momos: "Momos",
        session_initialized: "Session initialized. Select privileges above.",
        connecting: "Connecting to client:",
        checking_session: "Checking for active session",
        no_active_session: "No active session",
        connect_to_kali: "Connect to Kali"
    },

    overview: {
        summary: "Summary",
        agent_logs: "Agent Logs"
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
