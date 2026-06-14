<template>
  <div class="column">
    <!-- First row -->
    <div class="row full-width">
      <!-- Targets -->
      <div class="border field">
        <span class="text-red" style="padding-left: 10px">Targets</span>
        <div class="separator" />
        <!-- Input box-->
        <div class="row">
          <div class="terminal-input-group" style="margin: 5px; width: 100%">
            <input
              v-model="target"
              class="input-field"
              placeholder="ENTER IPv4/IPv6 OR DOMAIN ADDRESS"
            />
          </div>
          <div class="add-button button border" @click="">+</div>
        </div>
      </div>

      <!-- Summary -->
      <div class="border field">
        <span class="text-red" style="padding-left: 10px">Summary</span>
        <div class="separator" />
      </div>
    </div>
    <!-- Second row -->
    <div class="row">
      <div class="border field">
        <span class="text-red" style="padding-left: 10px">Agent Info</span>
        <div class="separator" />
        <div>
            
        </div>
      </div>

      <div class="border field">
        <span class="text-red" style="padding-left: 10px">Agent Logs</span>
        <div class="separator" />
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref } from "vue";

const target = ref<string>();
</script>

<style scoped lang="css">
.row {
  display: flex;
  justify-content: space-evenly;
}

.field {
  width: 50%;
  margin: 5px;
}

.input-field {
  width: 100%;
}

.add-button {
  aspect-ratio: 1;
  width: 4%;

  font-size: x-large;
  margin: 5px;
}
</style>
