<template>
  <div class="overflow-auto">
    <div v-on:focus="$event.target.select()" ref="rawhttp" class="rawhttp">
      {{ data }}
    </div>
    <br />
    <div style="float: right">
      <i
        @click="copyToClipboard()"
        title="copy to clipboard"
        class="pi pi-copy pointer"
      ></i>
      &nbsp;
      <i
        @click="decodeUri()"
        title="decode uri"
        class="pi pi-percentage pointer"
      ></i>
      &nbsp;
      <i
        @click="decodeUnicode()"
        title="decode unicode"
        class="pi pi-code pointer"
      ></i>
    </div>
  </div>
</template>

<script>
import { copyToClipboardHelper, decodeUnicodeString } from "../../helpers.js";
export default {
  props: ["label", "data"],
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
