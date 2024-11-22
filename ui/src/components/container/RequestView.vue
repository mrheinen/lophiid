<template>
  <div class="">
    <div>
      <FieldSet legend="Request details" :toggleable="false">
        <RequestTable :request="request"></RequestTable>
      </FieldSet>
    </div>
    <div>
    <FieldSet legend="Context" :toggleable="false">
      <div v-if="localDescription">
        <p>
        {{ localDescription.ai_description }}
        </p>
        <br />
        <p>
        {{ localConclusion }}
        </p>
      </div>
    <PrimeTabs value="0">
    <TabList>
        <PrimeTab value="0">HTTP Request</PrimeTab>
        <PrimeTab value="1" v-if="request.raw_response">HTTP Response</PrimeTab>
        <PrimeTab value="2" v-if="metadata.length">Metadata</PrimeTab>
        <PrimeTab value="3" v-if="localWhois">Whois</PrimeTab>
        <PrimeTab value="4" v-if="request.content_dynamic == true">Debug</PrimeTab>
    </TabList>

        <TabPanels>
        <TabPanel value="0">
          <RawHttpCard
            v-if="request.raw"
            label="HTTP request"
            :data="request.raw"
          ></RawHttpCard>
        </TabPanel>
        <TabPanel value="1" v-if="request.raw_response">
          <RawHttpCard
            v-if="request.raw_response"
            label="Raw response"
            :data="request.raw_response"
          ></RawHttpCard>

        </TabPanel>
        <TabPanel v-if="metadata.length" value="2">
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
        </TabPanel>

        <TabPanel value="3" v-if="localWhois">
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
          <br />

          <pre v-if="localWhois.data" class="whois">{{ localWhois.data }}</pre>
          <pre v-if="localWhois.rdap_string" class="whois">{{
            localWhois.rdap_string
          }}</pre>
        </TabPanel>
        <TabPanel value="4" v-if="request.content_dynamic == true">
          <div v-if="request.content_dynamic == true">
              <pre class="rawrequest">{{ request.raw_response }}</pre>
          </div>
        </TabPanel>
    </TabPanels>
    </PrimeTabs>
    </FieldSet>
    </div>

  </div>
</template>

<script>
import RawHttpCard from "../cards/RawHttpCard.vue";
import RequestTable from "../cards/RequestDetailsTable.vue";
export default {
  components: { RawHttpCard, RequestTable },
  props: ["request", "metadata", "whois", "description"],
  inject: ["config"],
  data() {
    return {
      localWhois: null,
      localDescription: null,
      localConclusion: null,
      localMetadata: [],
      localBase64Metadata: [],
      localLinkMetadata: [],
      localTCPMetadata: [],
      localNetcatMetadata: [],
      localUnicodeMetadata: [],
    };
  },
  methods: {},
  watch: {
    whois() {
      if (this.whois == null) {
        this.localWhois = null;
      } else {
        this.localWhois = Object.assign({}, this.whois);
      }
    },
    description(){
      if (this.description == null) {
        this.localDescription = null;
        this.localConclusion = null;
      } else {
        this.localDescription = Object.assign({}, this.description);
        if (this.localDescription.ai_malicious == "true") {
          if (this.localDescription.ai_vulnerability_type != "") {
            this.localConclusion = "AI conclusion: this request is malicious and tries to exploit a \"" +
              this.localDescription.ai_vulnerability_type + "\" vulnerability type.";
          } else {
            this.localConclusion = "AI conclusion: this request is malicous.";
          }
        } else {
            this.localConclusion = "AI conclusion: this request is not malicous";
        }
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
  max-width: 640px;
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
