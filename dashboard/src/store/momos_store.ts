import { defineStore } from "pinia";
import { getAllProjects, putProject, type PutProjectData } from "@/api";
import type { tProject, tTarget } from "@/types";

interface State {
    openedProject: string,
  projects: tProject[];
  targets: tTarget[];
}

export const useMomosStore = defineStore("momos", {
  state: (): State => ({
    projects: [],
    targets: [],
    openedProject: ''
  }),

  getters: {
    getProjects: (state) => state.projects,
    getProjectsTargets: (state) => (projectID: string) =>
      state.targets.filter((t) => t.projectID === projectID),
  },

  actions: {
    async reload_projects(){     
      const result = await getAllProjects()

      if(result.response?.status !== 200){
        throw Error("Could not load database")
      }
      
      this.projects = result.data || []

      if (this.openedProject === ''){
          this.openedProject = this.projects.at(0)?.id || ''
        }
    },

    async addProject(name: string) {
        // Try adding project     
        const result = await putProject({body: {name: name}})

        if(result.response?.status !== 200 || result.data === undefined){
          throw Error("Could not add new project")
        }
        
        this.projects.push(result.data)

        if (this.openedProject === ''){
          this.openedProject = this.projects.at(0)?.id || ''
        }
    },

    addProjectsTarget(target: tTarget){
        console.log('pow')

        //Check if projectID exists
        if (!this.projects.some(p => p.id === target.projectID)) {
            return
        }

        this.targets.push(target)
    },
    deleteTarget(targetID: string){
      this.targets = this.targets.filter(t => t.id !== targetID)
    }
  }
});
