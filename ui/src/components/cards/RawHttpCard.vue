<template>
  <div class="raw-http-wrap">
    <div
      ref="rawhttp"
      class="raw-http-content"
      @focus="$event.target.select()"
    >{{ data }}</div>
    <div class="raw-http-actions">
      <PrimeButton
        v-tooltip.bottom="'Copy to clipboard'"
        icon="pi pi-copy"
        severity="secondary"
        text
        size="small"
        @click="copyToClipboard()"
      />
      <PrimeButton
        v-tooltip.bottom="'Decode URI'"
        icon="pi pi-percentage"
        severity="secondary"
        text
        size="small"
        @click="decodeUri()"
      />
      <PrimeButton
        v-tooltip.bottom="'Decode Unicode'"
        icon="pi pi-code"
        severity="secondary"
        text
        size="small"
        @click="decodeUnicode()"
      />
    </div>
  </div>
</template>

<script>
import { copyToClipboardHelper, decodeUnicodeString } from "../../helpers.js";
export default {
  props: {
    "label": {
      type: String,
      required: true
    },
    "data": {
      type: String,
      required: true
    }
  },
  methods: {
    copyToClipboard() {
      copyToClipboardHelper(this.$refs.rawhttp.textContent);
      this.$toast.info("Copied");
    },
    decodeUri() {
      this.$refs.rawhttp.textContent = decodeURIComponent(
        this.$refs.rawhttp.textContent
      );
    },
    decodeUnicode() {
      this.$refs.rawhttp.textContent = decodeUnicodeString(
        this.$refs.rawhttp.textContent
      );
    },
  },
};
</script>

<style scoped>
.raw-http-wrap {
  position: relative;
}

.raw-http-content {
  overflow: auto;
  background-color: var(--p-surface-100);
  border: 1px solid var(--p-surface-200);
  border-radius: var(--p-border-radius);
  padding: 0.75rem;
  max-width: 100%;
  max-height: 500px;
  font-family: 'Roboto Mono', 'Courier New', monospace;
  font-size: 0.85rem;
  line-height: 1.5;
  word-break: normal !important;
  word-wrap: normal !important;
  white-space: pre !important;
}

.raw-http-actions {
  display: flex;
  justify-content: flex-end;
  gap: 0.25rem;
  margin-top: 0.5rem;
}
</style>
