<template>
  <div class="rounded overflow-hidden shadow-lg rcard">
    <div class="text-xl rcardlabel">
      <slot name="label">{{ mylabel }}</slot>
    </div>
    <slot></slot>
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
  margin-bottom: 30px;
  border-width: 1px 1px 0 1px;
  border-color: #cbd5e1;
  margin-right: 15px;
  padding-left: 10px;
  padding-bottom: 10px;
}

.rcardlabel {
  position: relative;
  margin-bottom: 10px;
}
</style>
