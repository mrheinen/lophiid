<template>
  <div class="info-card">
    <div class="info-card-header">
      <slot name="label">
        <span class="info-card-title">{{ mylabel }}</span>
      </slot>
    </div>
    <div class="info-card-body">
      <slot />
    </div>
  </div>
</template>

<script>
export default {
  props: {
    "mylabel": {
      type: String,
      required: true
    }
  },
};
</script>

<style scoped>
.info-card {
  background: var(--p-surface-0);
  border: 1px solid var(--p-surface-200);
  border-radius: var(--p-border-radius);
  margin-bottom: 1rem;
  overflow: hidden;
}

.info-card-header {
  padding: 0.75rem 1rem;
  background: var(--p-surface-50);
  border-bottom: 1px solid var(--p-surface-200);
}

.info-card-title {
  font-size: 0.875rem;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.04em;
  color: var(--p-text-muted-color);
}

.info-card-body {
  padding: 1rem;
}
</style>
