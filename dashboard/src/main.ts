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

app.mount('#app')
