<template>
  <Teleport to="body">
    <Transition name="fade">
      <div v-if="visible" class="dialog-overlay" @click.self="visible = false">
        <div class="dialog-content border">
          <div class="dialog-header" v-if="showTitle">
            <slot name="title"
              ><h3 class="no-margin truncate-text">{{ title }}</h3></slot
            >
            <button v-if="!noCloseButton" class="button border" @click="visible = false">✕</button>
          </div>

          <div class="dialog-body">
            <slot />
          </div>

          <div class="dialog-footer">
            <slot name="footer"> </slot>
          </div>
        </div>
      </div>
    </Transition>
  </Teleport>
</template>

<script setup lang="ts">
const visible = defineModel("visible", { type: Boolean, default: false });
withDefaults(defineProps<{ title?: string; showTitle?: boolean, noCloseButton?: boolean }>(), {
  showTitle: true,
  noCloseButton: false
});
</script>

<style scoped>
.dialog-header {
  display: flex;
  justify-content: center;
  margin-bottom: 10px;
}

.button {
  align-self: center;
  margin-left: auto;
  margin-right: -10px;
}

.dialog-overlay {
  position: fixed;
  top: 0;
  left: 0;
  width: 100%;
  height: 100%;
  background: rgba(0, 0, 0, 0.5);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 40;
}
.dialog-content {
  backdrop-filter: blur(4px);
  background-color: var(--black);
  padding-inline: 20px;
  padding-top: 10px;
  padding-bottom: 20px;
  border-radius: 8px;
  width: auto;
  z-index: 45;
}
.fade-enter-active,
.fade-leave-active {
  transition: opacity 0.3s;
}
.fade-enter-from,
.fade-leave-to {
  opacity: 0;
}
</style>
