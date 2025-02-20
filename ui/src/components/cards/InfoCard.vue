<template>
  <div style="margin-top: 20px">
    <div
      class="static rounded overflow-visible shadow-md shadow-stone-500/50 px-4
      mr-5 mb-14 rcard"
    >
      <div
        class="relative z-40 -top-5 left-0 bg-white rounded border text-xl max-w-3/10"
        style="border-color: #cbd5e1"
      >
        <slot name="label">
          <p class="font-mono text-2xl antialiased font-medium">
            {{ mylabel }}
          </p>
        </slot>
      </div>
      <slot></slot>
    </div>
  </div>
</template>

<script>
export default {
  props: ["mylabel"],
  data() {
    return {};
  },
  methods: {},
  watch: {},
};
</script>

<style scoped>
.rcard {
  background-color: white;
  border-width: 1px 1px 0 1px;
  border-color: #cbd5e1;
  padding-bottom: 10px;
}
</style>
