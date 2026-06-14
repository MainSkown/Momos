import { defineStore, mapStores } from "pinia";
import { defineComponent } from "vue";
import type { tProject, tTarget } from "@/types";

interface State {
    openedProject: string,
  projects: tProject[];
  targets: tTarget[];
}

export const useMomosStore = defineStore("momos", {
  state: (): State => ({
    projects: [
      { id: "123", name: "test1" },
      { id: "213", name: "test2" },
    ],
    targets: [],
    openedProject: ''
  }),

  getters: {
    getProjects: (state) => state.projects,
    getProjectsTargets: (state) => (projectID: string) =>
      state.targets.filter((t) => t.projectID === projectID),
  },

  actions: {
    addProject(project: tProject) {
        /* Ensure unique ID */
        project.id = crypto.randomUUID()

        this.projects.push(project)
    },

    addProjectsTarget(target: tTarget){
        console.log('pow')

        //Check if projectID exists
        if (!this.projects.some(p => p.id === target.projectID)) {
            return
        }

        this.targets.push(target)
    }
  }
});
