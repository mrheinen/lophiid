<template>
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
          <tr>
            <th>Honeypot IP</th>
            <td>
              <a :href="'/requests?q=honeypot_ip:' + localRequest.honeypot_ip">
                {{ localRequest.honeypot_ip }}
              </a>
            </td>
          </tr>
          <tr>
            <th>Honeypot port</th>
            <td>
              <a :href="'/requests?q=port:' + localRequest.port">
                {{ localRequest.port }}
              </a>
            </td>
          </tr>
          <tr>
            <th>Base Hash</th>
            <td>
                {{ localRequest.base_hash }}
                <a :href="'/requests?q=base_hash:' + localRequest.base_hash">
                  <i class="pi pi-search" title="find similar requests"></i>
                </a>
            </td>
          </tr>
          <tr v-if="localRequest.tags">
            <th>Labels</th>
            <td>
              <div v-for="tag in localRequest.tags"
                :key="tag.tag.id"
                :title="tag.tag.description"
                class="mytag"
                :style="'background-color: #' + tag.tag.color_html"
                >
                <a :href="'/requests?q=label:' + tag.tag.name">
                  {{ tag.tag.name }}&nbsp;
                </a>
              </div>
            </td>
          </tr>
        </tbody>
      </table>
    </FieldSet>
  </div>
   <br />
  <P0fResultCard v-if="localRequest.p0f_result" label="p0f result"
    :p0f="localRequest.p0f_result"></P0fResultCard>
  <br />
  <RawHttpCard v-if="localRequest.raw" label="HTTP request"
    :data="localRequest.raw"></RawHttpCard>
  <br />
  <RawHttpCard v-if="localRequest.raw_response" label="Raw response"
    :data="localRequest.raw_response"></RawHttpCard>
  <br />

  <div v-if="metadata.length" class="card">
    <FieldSet legend="Metadata" :toggleable="true">
      <div v-if="localUnicodeMetadata.length">
        <div style="width: 700px">
        <label class="label">Decoded unicode strings</label>
        <div v-for="meta in localUnicodeMetadata" :key="meta.id">
          <highlightjs autodetect :code="meta.data" />
        </div>
        </div>
      </div>

      <div v-for="meta in localBase64Metadata" :key="meta.id">
        <div style="width: 700px">
          <label class="label">Decoded base64 string</label>
          <highlightjs autodetect :code="meta.data" />
        </div>
      </div>

      <div v-if="localLinkMetadata.length">
        <label class="label">Extracted URLs</label>
        <div v-for="meta in localLinkMetadata" :key="meta.id">
          <p>{{ meta.data }}</p>
        </div>
      </div>

     <div v-if="localTCPMetadata.length">
        <label class="label">Extracted TCP links</label>
        <div v-for="meta in localTCPMetadata" :key="meta.id">
          <p>{{ meta.data }}</p>
        </div>
      </div>
     <div v-if="localNetcatMetadata.length">
        <label class="label">Extracted netcat links</label>
        <div v-for="meta in localNetcatMetadata" :key="meta.id">
          <p>{{ meta.data }}</p>
        </div>
      </div>
    </FieldSet>
     <br />
  </div>
  <div v-if="localRequest.content_dynamic == true" class="card">
    <FieldSet legend="Customized response" :toggleable="true">
      <pre class="rawrequest">{{ localRequest.raw_response }}</pre>
    </FieldSet>
  </div>

  <br />
  <div v-if="localWhois" class="card">
    <FieldSet legend="WHOIS record" :toggleable="true">

      <table v-if="localWhois.country">
        <tbody>
          <tr>
            <th>Country</th>
            <td>
              {{ localWhois.country }}
            </td>
          </tr>
        </tbody>
      </table>
      <br/>

      <pre v-if="localWhois.data" class="whois">{{ localWhois.data }}</pre>
      <pre v-if="localWhois.rdap_string" class="whois">{{ localWhois.rdap_string }}</pre>
    </FieldSet>
  </div>

  <br />
</template>

<script>
import RawHttpCard from '../cards/RawHttpCard.vue';
import P0fResultCard from '../cards/P0fResultCard.vue';
export default {
  components: { RawHttpCard, P0fResultCard },
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
      localTCPMetadata: [],
      localNetcatMetadata: [],
      localUnicodeMetadata: [],
    };
  },
  methods: {
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
      this.localTCPMetadata = [];
      this.localNetcatMetadata = [];
      this.localUnicodeMetadata = [];
      for (var i = 0; i < this.metadata.length; i++) {
        if (this.metadata[i].type == "DECODED_STRING_BASE64") {
          this.localBase64Metadata.push(this.metadata[i]);
        } else if (this.metadata[i].type == "PAYLOAD_LINK") {
          this.localLinkMetadata.push(this.metadata[i]);
        } else if (this.metadata[i].type == "PAYLOAD_TCP_LINK") {
          this.localTCPMetadata.push(this.metadata[i]);
        } else if (this.metadata[i].type == "PAYLOAD_NETCAT") {
          this.localNetcatMetadata.push(this.metadata[i]);
        } else if (this.metadata[i].type == "DECODED_STRING_UNICODE") {
          this.localUnicodeMetadata.push(this.metadata[i]);
        }
      }
      this.localMetadata = this.metadata;
    },
  },
  created() {},
};
</script>

<style scoped>
code.hljs {
  height: 400px;
  width: 700px;
  overflow: auto;
}

.mytag {
  font-size: 0.8rem;
  display: inline-block;
  padding-right: 3px;
  padding-left: 3px;
  border-radius: 5px;
  margin-left: 10px;
}

table {
  border-collapse: collapse;
}

pre.whois {
  max-height: 400px;
  max-width: 700px;
  overflow: auto;
  background-color: #eeeeee;
  word-break: normal !important;
  word-wrap: normal !important;
  white-space: pre !important;
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

</style>
