<template>
  <div class="card">
    <FieldSet legend="Raw request" :toggleable="true">
      <pre class="rawrequest" v-if="localRequest.raw">{{
        localRequest.raw
      }}</pre>
    </FieldSet>
  </div>

  <br />
  <div v-if="metadata.length" class="card">
    <FieldSet legend="Metadata" :toggleable="true">
      <div v-for="meta in localBase64Metadata" :key="meta.id">
        <br />
        <div style="width: 700px;">
          <h6 class="subtitle is-6">Decoded base64 string</h6>
          <highlightjs autodetect :code="meta.data" />
        </div>
      </div>
      <div v-for="meta in localLinkMetadata" :key="meta.id">
        <p>{{ meta.data }}</p>
      </div>
    </FieldSet>
  </div>
</template>

<script>
export default {
  props: ["request", "metadata"],
  inject: ["config"],
  data() {
    return {
      localRequest: {
        parsed: {},
      },
      localMetadata: [],
      localBase64Metadata: [],
      localLinkMetadata: [],
    };
  },
  watch: {
    request() {
      this.localRequest = Object.assign({}, this.request);
    },
    metadata() {
      this.localBase64Metadata = [];
      this.localLinkMetadata = [];
      for (var i = 0; i < this.metadata.length; i++) {
        if (this.metadata[i].type == "DECODED_STRING_BASE64") {
          this.localBase64Metadata.push(this.metadata[i]);
        } else if (this.metadata[i].type == "PAYLOAD_LINK") {
          this.localLinkMetadata.push(this.metadata[i]);
        }
      }
      this.localMetadata = this.metadata;
    },
  },
  created() {},
};
</script>

<style scoped>
pre.rawrequest {
  max-height: 400px;
  max-width: 700px;
  overflow: auto;
  background-color: #eeeeee;
  word-break: normal !important;
  word-wrap: normal !important;
  white-space: pre !important;
}

code.hljs {
  height: 400px;
  width: 700px;
  overflow: auto;
}

pre.decoded {
  max-height: 100px;
  max-width: 700px;
  overflow: auto;
  background-color: #eeeeee;
  word-break: normal !important;
  word-wrap: normal !important;
  white-space: pre !important;
}
</style>
