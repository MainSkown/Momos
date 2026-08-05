import type { tTool } from '../types';

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
    name: 'AI'
  },
  {
    key: USER_SETTINGS_KEYS.USER_OPTIONS,
    name: 'User Options'
  }
]