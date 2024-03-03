<template>
  <div class="card">
    <FieldSet legend="Raw request" :toggleable="true">
      <pre
        v-on:focus="$event.target.select()"
        ref="rawrequest"
        class="rawrequest"
        v-if="localRequest.raw"
        >{{ localRequest.raw }}</pre
      >

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
      </div>
    </FieldSet>
  </div>

  <br />
  <div class="card">
    <FieldSet legend="Request details" :toggleable="true">
      <table>
        <tbody>
          <tr>
            <th>Request ID</th>
            <td>
              {{ localRequest.id }}
            </td>
          </tr>

          <tr>
            <th>Content ID</th>
            <td>
              <a :href="'/content?q=id:' + localRequest.content_id">
                {{ localRequest.content_id }}
              </a>
            </td>
          </tr>

          <tr>
            <th>Rule ID</th>
            <td>
              <a :href="'/rules?q=id:' + localRequest.rule_id">
                {{ localRequest.rule_id }}
              </a>
            </td>
          </tr>
          <tr v-if="localRequest.tags">
            <th>Tags</th>
            <td>
              <div v-for="tag in localRequest.tags" :key="tag.tag.id">
                {{ tag.tag.name }}&nbsp;
              </div>
            </td>
          </tr>
        </tbody>
      </table>
    </FieldSet>
  </div>
  <br />

  <div v-if="metadata.length" class="card">
    <FieldSet legend="Metadata" :toggleable="true">
      <div v-for="meta in localBase64Metadata" :key="meta.id">
        <br />
        <div style="width: 700px">
          <label class="label">Decoded base64 string</label>
          <highlightjs autodetect :code="meta.data" />
        </div>
      </div>
      <div v-if="localLinkMetadata">
        <label class="label">Extracted URLs</label>
        <div v-for="meta in localLinkMetadata" :key="meta.id">
          <p>{{ meta.data }}</p>
        </div>
      </div>
    </FieldSet>
  </div>
  <br />
  <div v-if="localRequest.content_dynamic == true" class="card">
    <FieldSet legend="Customized response" :toggleable="true">
      <pre class="rawrequest">{{ localRequest.raw_response }}</pre>
    </FieldSet>
  </div>

  <br />
  <div v-if="localWhois" class="card">
    <FieldSet legend="WHOIS record" :toggleable="true">
      <pre class="rawrequest">{{ localWhois.data }}</pre>
    </FieldSet>
  </div>

  <br />
</template>

<script>
import { copyToClipboardHelper } from "../../helpers.js";

export default {
  props: ["request", "metadata", "whois"],
  inject: ["config"],
  data() {
    return {
      localRequest: {
        parsed: {},
      },
      localWhois: null,
      localMetadata: [],
      localBase64Metadata: [],
      localLinkMetadata: [],
    };
  },
  methods: {
    copyToClipboard() {
      copyToClipboardHelper(this.$refs.rawrequest.textContent);
      this.$toast.info("Copied");
    },
    decodeUri() {
      this.$refs.rawrequest.textContent = decodeURIComponent(
        this.$refs.rawrequest.textContent
      );
    },
  },
  watch: {
    request() {
      this.localRequest = Object.assign({}, this.request);
    },

    whois() {
      if (this.whois == null) {
        this.localWhois = null;
      } else {
        this.localWhois = Object.assign({}, this.whois);
      }
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

table {
  border-collapse: collapse;
}

th,
td {
  padding-top: 2px;
  padding-bottom: 2px;
  padding-right: 8px;
}

th {
  color: #616060;
}

.pointer {
  cursor: pointer;
}
</style>
