<template>
  <HistoryList v-if="!selectedSessionId" @select="selectedSessionId = $event" />
  <SessionDetail
    v-else
    :session-id="selectedSessionId"
    @back="selectedSessionId = null"
  />
</template>

<script setup lang="ts">
// Owns only the list<->detail switch - everything else (filters, loaded
// sessions, the open session's own data) lives in HistoryList/
// SessionDetail themselves. A plain local ref (not store state) is enough
// since MainPage.vue unmounts this whole tool when switching away (see
// its own v-if branches) - there's nothing here worth surviving that.
import { ref } from "vue";
import HistoryList from "./HistoryList.vue";
import SessionDetail from "./SessionDetail.vue";

const selectedSessionId = ref<string | null>(null);
</script>
