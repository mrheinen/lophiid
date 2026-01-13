<template>
  <div class="overflow-auto">
    <div
      ref="rawhttp"
      class="rawhttp"
      @focus="$event.target.select()"
    >
      {{ data }}
    </div>
    <br>
    <div style="float: right">
      <i
        title="copy to clipboard"
        class="pi pi-copy pointer"
        @click="copyToClipboard()"
      />
      &nbsp;
      <i
        title="decode uri"
        class="pi pi-percentage pointer"
        @click="decodeUri()"
      />
      &nbsp;
      <i
        title="decode unicode"
        class="pi pi-code pointer"
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
div.rawhttp {
  overflow: auto;
  background-color: #eeeeee;
  max-width: 100%;
  word-break: normal !important;
  word-wrap: normal !important;
  white-space: pre !important;
}

.pointer {
  cursor: pointer;
}
</style>
