<template>
  <Transition name="fade">
    <div v-if="visible" class="dialog-overlay" @click.self="visible = false">
      <div class="dialog-content border">        
        <div class="dialog-header">
          <slot name="title"><h3 class="no-margin">Title</h3></slot>
          <button class="button border" @click="visible = false">✕</button>          
        </div>

        <div class="dialog-body">
          <slot />
        </div>

        <div class="dialog-footer">
          <slot name="footer">            
          </slot>
        </div>
      </div>
    </div>
  </Transition>
</template>

<script setup lang="ts">
const visible = defineModel("visible", { type: Boolean, default: false });
</script>

<style scoped>
.dialog-header{
    display: flex;
    justify-content: center;
    margin-bottom: 10px;
}

.button{
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
}
.dialog-content {
  backdrop-filter: blur(4px);
  padding-inline: 20px;
  padding-top: 10px;
  padding-bottom: 20px;
  border-radius: 8px;
  width: 400px;
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
