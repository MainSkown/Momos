import { defineStore } from "pinia";
import {
  getAllProjects,
  postProject,
  postTarget,
  getAllTargetsInProject,
  deleteTarget,
  updateTarget
} from "@/api";
import type { tProject, tTarget } from "@/types";

interface State {
  openedProject: string;
  projects: tProject[];
  targets: tTarget[];
  cmd_outputs: {[project_id: string]: string[]}
}

export const useMomosStore = defineStore("momos", {
  state: (): State => ({
    projects: [],
    targets: [],
    openedProject: "",
    cmd_outputs: {}
  }),

  getters: {
    getProjects: (state) => state.projects,
    getProjectsTargets: (state) => (projectID: string) =>
      state.targets.filter((t) => t.project_id === projectID),
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
    async deleteTarget(targetID: string) {
      const result = await deleteTarget({path: {target_id: targetID}})

      if (result.response?.status !== 204){
        throw Error('Could not delete target: ' + targetID)
      }

      this.targets = this.targets.filter((t) => t.id !== targetID);
    },

    async updateTarget(target: tTarget){
      const result = await updateTarget({body: {...target}, path: {target_id: target.id}})

      if (result.response?.status !== 200){
        throw Error('Could not update target: ' + target.id)
      }

      const index = this.targets.findIndex((t) => t.id === target.id)
      this.targets[index] = target
    }
  },
});