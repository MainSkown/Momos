import { defineStore } from "pinia";
import {
  getAllProjects,
  postProject,
  postTarget,
  type TargetBase,
} from "@/api";
import type { tProject, tTarget } from "@/types";

interface State {
  openedProject: string;
  projects: tProject[];
  targets: tTarget[];
}

export const useMomosStore = defineStore("momos", {
  state: (): State => ({
    projects: [],
    targets: [],
    openedProject: "",
  }),

  getters: {
    getProjects: (state) => state.projects,
    getProjectsTargets: (state) => (projectID: string) =>
      state.targets.filter((t) => t.project_id === projectID),
  },

  actions: {
    async reload_projects() {
      const result = await getAllProjects();

      if (result.response?.status !== 200) {
        throw Error("Could not load database");
      }

      this.projects = result.data || [];

      if (this.openedProject === "") {
        this.openedProject = this.projects.at(0)?.id || "";
      }
    },

    async addProject(name: string) {
      // Try adding project
      const result = await postProject({ body: { name: name } });

      if (result.response?.status !== 200 || result.data === undefined) {
        throw Error("Could not add new project");
      }

      this.projects.push(result.data);

      if (this.openedProject === "") {
        this.openedProject = this.projects.at(0)?.id || "";
      }
    },

    async addTarget2Project(name: string, projectID: string) {
      const result = await postTarget({
        body: {
          name: name,
          ipv4: null,
          ipv6: null,
          domain: null,
          description: null,
          ports: null,
        },
        path: { project_id: projectID },
      });

      if (result.response?.status !== 200 || result.data === undefined) {
        throw Error("Could not add new target");
      }

      this.targets.push(result.data);
    },
    deleteTarget(targetID: string) {
      this.targets = this.targets.filter((t) => t.id !== targetID);
    },
  },
});
