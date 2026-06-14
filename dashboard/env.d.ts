/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_API_URL: string
  readonly VITE_WS_URL: string
}

interface ImportMeta {
  readonly env: ImportMetaEnv
}

import 'vue-i18n'
import type { MessageSchema } from '@/i18n/locales'

declare module 'vue-i18n' {
  export interface DefineLocaleMessage extends MessageSchema {}
}