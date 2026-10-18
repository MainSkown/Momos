import './assets/main.css'

import { createApp } from 'vue'
import { createPinia } from 'pinia'
import App from './App.vue'
import Vue3Toastify, { type ToastContainerOptions } from 'vue3-toastify';
import 'vue3-toastify/dist/index.css';
import '@/assets/toast.css'
import {i18n} from '@/i18n/i18n.ts'

import '@fontsource/material-icons/index.css'
import '@fontsource/material-icons-outlined/index.css'
import "md-editor-v3/lib/style.css";
import "@/assets/md-editor.css";
import { useMomosStore } from '@/store/momos_store'
import { applyPersistedAccentColor } from '@/bootstrap/applyPersistedAccentColor'
import { registerAgentNotificationHooks } from '@/websockets/notification_hooks'

const pinia = createPinia()
const app = createApp(App)

app.use(pinia)
app.use(
  Vue3Toastify,
  {
    autoClose: 3000,
    // ...
  } as ToastContainerOptions,
)
app.use(i18n)

// Applied before mount so the persisted accent color is already in place
// for the first render - see applyPersistedAccentColor's own docstring.
await applyPersistedAccentColor(useMomosStore())

// Registered once, globally, regardless of which page/dialog is open - the
// user expects a notification even when nowhere near the relevant project.
registerAgentNotificationHooks()

app.mount('#app')