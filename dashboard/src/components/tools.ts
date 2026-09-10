import type { tTool } from '../types';
import {
  getDownloadableModels,
  getModelsList,
  type OllamaModelData,
} from '@/api';
import { ref, type Ref } from 'vue';

export enum TOOLS_KEYS {
  OVERVIEW = 'overview',
  VULNERABILITIES = 'vulns',
  PROJECT_CONFIGURATION = 'p_config'
}

export const tools: tTool[] = [
  {
    key: TOOLS_KEYS.OVERVIEW,
    name: 'tools.overview'
  },
  {
    key: TOOLS_KEYS.VULNERABILITIES,
    name: "tools.vulnerabilities",
  },
  {
    key: TOOLS_KEYS.PROJECT_CONFIGURATION,
    name: "tools.project_settings",
  },
]

export enum USER_SETTINGS_KEYS {
  AI = 'ai',
  USER_OPTIONS = 'user-options'
}

export const user_settings: tTool[] = [
  {
    key: USER_SETTINGS_KEYS.AI,
    name: 'settings.ai'
  },
  {
    key: USER_SETTINGS_KEYS.USER_OPTIONS,
    name: 'settings.user_options'
  }
]

class AIModelsManager {
  private static instance: AIModelsManager;

  public readonly downloadable_models: Ref<OllamaModelData[]> = ref([]);
  public readonly installed_models: Ref<OllamaModelData[]> = ref([]);

  private constructor() {}

  public static getInstance(): AIModelsManager {
    if (AIModelsManager.instance === undefined) {
      AIModelsManager.instance = new AIModelsManager();
    }

    return AIModelsManager.instance;
  }

  public async initialize(): Promise<void> {
    await this.refreshDownloadableModels();
    await this.refreshInstalledModels();
  }

  public async refreshDownloadableModels(): Promise<void> {
    const result = await getDownloadableModels();
    if (result.error) {
      console.error(result.error);
      return;
    }

    if (result.data === undefined) {
      console.error(
        'Function getDownloadableModels returned empty without server error',
      );
      return;
    }

    this.downloadable_models.value = result.data.models;
  }

  public async refreshInstalledModels(): Promise<void> {
    this.installed_models.value = await this.getInstalledModels();
  }

  public getRecommendedAgentModels(): OllamaModelData[] {
    return this.downloadable_models.value.filter((m) => m.recommended === 'agent');
  }

  public getRecommendedParsingModels(): OllamaModelData[] {
    return this.downloadable_models.value.filter((m) => m.recommended === 'parsing');
  }

  public getModelsByFamily(): Record<string, OllamaModelData[]> {
    const result: Record<string, OllamaModelData[]> = {};
    this.downloadable_models.value.forEach((m) => {
      if (result[m.family] === undefined) {
        result[m.family] = [];
      }

      result[m.family]?.push(m);
    });

    return result;
  }

  public isInstalled(modelName: string): boolean {
    return this.installed_models.value.find((m) => m.name === modelName) !== undefined;
  }

  private async getInstalledModels(): Promise<OllamaModelData[]> {
    const result = await getModelsList();

    if (result.error) {
      console.error(result.error);
      return [];
    }

    if (result.data === undefined) {
      console.error('Function getModelsList returned empty without server error');
      return [];
    }

    return result.data.models;
  }
}

export const aiModelsManager = AIModelsManager.getInstance();