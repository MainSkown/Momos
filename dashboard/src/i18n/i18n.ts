import { createI18n } from "vue-i18n"
import { messages } from './locales';
import type { MessageSchema } from "./locales"


export type AppLocales = 'en'

export const i18n = createI18n<[MessageSchema], AppLocales>({
    legacy: false,
    locale: 'en',
    messages: messages
})