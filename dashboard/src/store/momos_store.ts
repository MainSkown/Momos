import { defineStore } from "pinia";
import {
  getAllProjects,
  postProject,
  deleteProject,
  postTarget,
  getAllTargetsInProject,
  deleteTarget,
  updateTarget,
  getOllamaDownloadQueueDetails,
  type OllamaDownloadProgress,
  downloadOllamaModel,
  type ModelPullingUpdate,
  isProjectAgentRunning,
  type AgentRunStatus,
  type ProjectSettings,
  getTargetAttackVectors,
  type ResponseAttackVector,
  type AttackVectorUpdate,
} from "@/api";
import type { tProject, tTarget } from "@/types";
import { useWebSocketClient } from "@/websockets/websocket_client";

type tCmd = { line: string; type: "cmd" | "error" | "user" | "system"; user?: string };

type tDownloadObject = {
  model_name: string;
  download_start: number;
  last_progress: OllamaDownloadProgress | null;
  last_update_time: number | null;
  status: string;
};

interface State {
  openedProject: string;
  projects: tProject[];
  targets: tTarget[];
  cmd_outputs: {
    [project_id: string]: { [session: string]: tCmd[] };
  };
  download_queue: tDownloadObject[];
  running_targets: {
    [project_id: string]: string | null;
  };
  project_settings: {
    [project_id: string]: ProjectSettings;
  };
  attack_vectors: {
    [target_id: string]: ResponseAttackVector[];
  };
}

// Registered once for the app's lifetime (not per-component-mount, unlike
// _downloadModelHook below) - loadRunningTarget can be called repeatedly
// (once per project switch) without stacking duplicate hooks.
let runningTargetHookRegistered = false;

function registerRunningTargetHook() {
  if (runningTargetHookRegistered) return;
  runningTargetHookRegistered = true;

  const ws_client = useWebSocketClient();
  ws_client.add_hook("AgentRunStatus", (message) => {
    if (message.error) return;

    const statusMessage = message as AgentRunStatus;
    const store = useMomosStore();

    store.running_targets[statusMessage.project_id] = statusMessage.running
      ? statusMessage.target_id
      : null;
  });
}

// Same singleton-guarded pattern as registerRunningTargetHook above -
// loadAttackVectors can be called once per Overview mount per target
// without ever stacking duplicate AttackVectorUpdate hooks.
let attackVectorHookRegistered = false;

function registerAttackVectorHook() {
  if (attackVectorHookRegistered) return;
  attackVectorHookRegistered = true;

  const ws_client = useWebSocketClient();
  ws_client.add_hook("AttackVectorUpdate", (message) => {
    if (message.error) return;

    const update = message as AttackVectorUpdate;
    const store = useMomosStore();
    const vectors = store.attack_vectors[update.target_id] ?? [];
    const index = vectors.findIndex((v) => v.id === update.vector.id);

    if (index === -1) {
      store.attack_vectors[update.target_id] = [...vectors, update.vector];
    } else {
      vectors[index] = update.vector;
      store.attack_vectors[update.target_id] = vectors;
    }
  });
}

export const useMomosStore = defineStore("momos", {
  state: (): State => ({
    projects: [],
    targets: [],
    openedProject: "",
    cmd_outputs: {},
    download_queue: [],
    running_targets: {},
    project_settings: {},
    attack_vectors: {},
  }),

  getters: {
    getProjects: (state) => state.projects,
    getProjectsTargets: (state) => (projectID: string) =>
      state.targets.filter((t) => t.project_id === projectID),
    getRunningTarget: (state) => (projectID: string) =>
      state.running_targets[projectID] ?? null,
    getProjectSettings: (state) => (projectID: string) =>
      state.project_settings[projectID] ?? null,
    getAttackVectors: (state) => (targetID: string) =>
      state.attack_vectors[targetID] ?? [],
    getQueueObjectCompletion:
      (state) =>
      (model_name: string): { completed: number; total: number } => {
        const q = state.download_queue.find(
          (item) => item.model_name === model_name,
        );

        if (
          !q ||
          q.last_progress?.completed == null ||
          q.last_progress.total == null
        ) {
          return { completed: 0, total: 0 };
        }

        if (q.status === "done") {
          return { completed: 1, total: 1 };
        }

        return {
          completed: q.last_progress.completed,
          total: q.last_progress.total,
        };
      },
  },

  actions: {
    /* Projects */
    async reloadProjects() {
      const result = await getAllProjects();

      if (result.response?.status !== 200) {
        throw Error("Could not load projects");
      }

      this.projects = result.data || [];

      if (this.openedProject === "") {
        this.openedProject = this.projects.at(0)?.id || "";
      }
    },

    async addProject(
      name: string,
      base_model_name: string,
      parsing_model_name: string,
    ) {
      // Try adding project
      const result = await postProject({
        body: {
          name: name,
          base_model_name: base_model_name,
          parsing_model_name: parsing_model_name,
        },
      });

      if (result.response?.status !== 200 || result.data === undefined) {
        throw Error("Could not add new project");
      }

      this.projects.push(result.data);

      if (this.openedProject === "") {
        this.openedProject = this.projects.at(0)?.id || "";
      }
    },

    async deleteProject(projectID: string) {
      const result = await deleteProject({ path: { project_id: projectID } });

      if (result.response?.status !== 204) {
        throw Error("Could not delete project: " + projectID);
      }

      this.projects = this.projects.filter((project) => project.id !== projectID);
      this.targets = this.targets.filter((target) => target.project_id !== projectID);
      delete this.cmd_outputs[projectID];

      if (this.openedProject === projectID) {
        this.openedProject = this.projects.at(0)?.id || "";
      }
    },

    /* Targets */
    async loadTargets(projectID: string) {
      const result = await getAllTargetsInProject({
        path: { project_id: projectID },
      });

      if (result.response?.status !== 200) {
        throw Error("Could not load targets");
      }

      this.targets = [
        ...this.targets,
        ...(result.data?.filter(
          // Filter out if for some reason loads the same targets
          (newT) => !this.targets.some((oldT) => oldT.id === newT.id),
        ) || []),
      ];
    },

    async addTarget2Project(name: string, projectID: string) {
      const result = await postTarget({
        body: {
          name: name,
          ipv4: null,
          ipv6: null,
          description: null,
          ports: null,
          task_duration: null
        },
        path: { project_id: projectID },
      });

      if (result.response?.status !== 200 || result.data === undefined) {
        throw Error("Could not add new target");
      }

      this.targets.push(result.data);
    },
    async deleteTarget(targetID: string) {
      const result = await deleteTarget({ path: { target_id: targetID } });

      if (result.response?.status !== 204) {
        throw Error("Could not delete target: " + targetID);
      }

      this.targets = this.targets.filter((t) => t.id !== targetID);
    },

    async updateTarget(target: tTarget) {
      const result = await updateTarget({
        body: { ...target },
        path: { target_id: target.id },
      });

      if (result.response?.status !== 200) {
        throw Error("Could not update target: " + target.id);
      }

      const index = this.targets.findIndex((t) => t.id === target.id);
      this.targets[index] = target;
    },

    setProjectSettings(projectID: string, settings: ProjectSettings) {
      this.project_settings[projectID] = settings;
    },

    async loadRunningTarget(projectID: string) {
      registerRunningTargetHook();

      const result = await isProjectAgentRunning({
        path: { project_id: projectID },
      });

      if (result.error || result.data === undefined) {
        throw Error("Could not load running target status: " + projectID);
      }

      this.running_targets[projectID] = result.data.running
        ? (result.data.target_id ?? null)
        : null;
    },

    async loadAttackVectors(projectID: string, targetID: string) {
      registerAttackVectorHook();

      const result = await getTargetAttackVectors({
        path: { project_id: projectID, target_id: targetID },
      });

      if (result.error || result.data === undefined) {
        throw Error("Could not load attack vectors: " + targetID);
      }

      this.attack_vectors[targetID] = result.data;
    },

    /* --- Commands --- */
    pushCmdLine(
      project_id: string,
      session: string,
      line: string,
      type: tCmd["type"],
      user?: string,
    ) {
      if (!this.cmd_outputs[project_id]) this.cmd_outputs[project_id] = {};
      if (!this.cmd_outputs[project_id][session]) this.cmd_outputs[project_id][session] = [];

      this.cmd_outputs[project_id][session].push({
        line,
        type,
        user,
      });
    },

    /** Drops a closed session's own output history - called when a tab
     * closes (its own explicit close, or "exit"). Session names are never
     * reused (see kali_user.py's auto-numbering), so this is just plain
     * cleanup, not needed to avoid a future session inheriting stale
     * output - without it cmd_outputs would just grow forever across a
     * long console lifetime. */
    clearCmdLines(project_id: string, session: string) {
      delete this.cmd_outputs[project_id]?.[session];
    },

    /* --- Managing Ollama --- */
    async loadQueue() {
      const result = await getOllamaDownloadQueueDetails();

      if (result.error || result.data === undefined) {
        throw Error("Could not load queue details");
      }
      const queue = [result.data.current, ...result.data.queue];

      queue.forEach((name) => {
        if (name !== null) this._downloadModelHook(name);
      });
    },

    _downloadModelHook(model_name: string) {
      const download_obj: tDownloadObject = {
        model_name: model_name,
        last_progress: null,
        download_start: Date.now(),
        last_update_time: null,
        status: "queued",
      };

      // Add model to queue
      this.download_queue.push(download_obj);

      const ws_client = useWebSocketClient();

      // Listen to updates
      const hook = ws_client.add_hook("ModelPullingUpdate", (message) => {
        if (message.error) {
          console.error(message.error.message);
          return;
        }

        message = message as ModelPullingUpdate; // Convert message

        if (message.progress.model !== model_name) return;

        const queue_obj = this.download_queue.find(
          (q) => q.model_name === model_name,
        );

        if (queue_obj) {
          queue_obj.last_update_time = Date.now();
          const progress = message.progress;

          if (queue_obj.status === "queued") {
            queue_obj.download_start = Date.now();
          }

          if (progress.completed && progress.total) {
            queue_obj.last_progress = message.progress;

            queue_obj.status = message.progress.status;
          }
        }

        // finished downloading
        if (message.progress.status === "success") {
          this.download_queue = this.download_queue.filter(
            (q) => q.model_name !== model_name,
          );
          hook?.delete();
        }
      });
    },

    async downloadModel(model_name: string) {
      const result = await downloadOllamaModel({
        body: { model_name: model_name },
      });

      if (result.error || result.response?.status !== 202) {
        throw Error("Could not download model: " + model_name);
      }

      this._downloadModelHook(model_name);
    },
  },
});
