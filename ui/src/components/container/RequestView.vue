<template>
  <div>
    <div>
      <InfoCard mylabel="Request details">
        <template #default>
          <RequestTable :request="request" />
        </template>
      </InfoCard>
    </div>
    <div>
      <InfoCard mylabel="AI description">
        <template #default>
          <div v-if="localDescription && localDescription.ai_description">
            <p>
              {{ localDescription.ai_description }}
            </p>
            <br>
            <p>
              {{ localConclusion }}
            </p>
            <i
              v-if="localDescription.review_status == config.reviewStatusOk"
              class="pi pi-thumbs-up-fill"
              @click="toggleReviewOk(localDescription.cmp_hash)"
            />
            <i
              v-else
              class="pi pi-thumbs-up"
              @click="toggleReviewOk(localDescription.cmp_hash)"
            />
            &nbsp;
            <i
              v-if="localDescription.review_status == config.reviewStatusNok"
              class="pi pi-thumbs-down-fill"
              @click="toggleReviewNok(localDescription.cmp_hash)"
            />
            <i
              v-else
              class="pi pi-thumbs-down"
              @click="toggleReviewNok(localDescription.cmp_hash)"
            />
          </div>
        </template>
      </InfoCard>
    </div>
    <div>
      <InfoCard mylabel="Request context">
        <template #default>
          <PrimeTabs value="0">
            <TabList>
              <PrimeTab value="0">
                HTTP Request
              </PrimeTab>
              <PrimeTab
                v-if="request.raw_response"
                value="1"
              >
                HTTP Response
              </PrimeTab>
              <PrimeTab
                v-if="metadata.length"
                value="2"
              >
                Metadata
              </PrimeTab>
              <PrimeTab
                v-if="localWhois"
                value="3"
              >
                Whois
              </PrimeTab>
              <PrimeTab value="4">
                Debug
              </PrimeTab>
            </TabList>

            <TabPanels>
              <TabPanel value="0">
                <RawHttpCard
                  v-if="request.parsed.raw"
                  label="HTTP request"
                  :data="request.parsed.raw"
                />
              </TabPanel>
              <TabPanel
                v-if="request.raw_response"
                value="1"
              >
                <RawHttpCard
                  v-if="request.raw_response"
                  label="Raw response"
                  :data="request.raw_response"
                />
              </TabPanel>
              <TabPanel
                v-if="metadata.length"
                value="2"
              >
                <div v-if="localUnicodeMetadata.length">
                  <div style="width: 700px">
                    <label class="label">Decoded unicode strings</label>
                    <div
                      v-for="meta in localUnicodeMetadata"
                      :key="meta.id"
                    >
                      <highlightjs
                        autodetect
                        :code="meta.data"
                      />
                    </div>
                  </div>
                </div>

                <div
                  v-for="meta in localBase64Metadata"
                  :key="meta.id"
                >
                  <div style="width: 700px">
                    <label class="label">Decoded base64 string</label>
                    <highlightjs
                      autodetect
                      :code="meta.data"
                    />
                  </div>
                </div>

                <div v-if="localLinkMetadata.length">
                  <label class="label">Extracted URLs</label>
                  <div
                    v-for="meta in localLinkMetadata"
                    :key="meta.id"
                  >
                    <p>{{ meta.data }}</p>
                  </div>
                </div>

                <div v-if="localTCPMetadata.length">
                  <label class="label">Extracted TCP links</label>
                  <div
                    v-for="meta in localTCPMetadata"
                    :key="meta.id"
                  >
                    <p>{{ meta.data }}</p>
                  </div>
                </div>

                <div v-if="localPingMetadata.length">
                  <label class="label">Extracted ping requests</label>
                  <div
                    v-for="meta in localPingMetadata"
                    :key="meta.id"
                  >
                    <p>{{ meta.data }}</p>
                  </div>
                </div>

                <div v-if="localNetcatMetadata.length">
                  <label class="label">Extracted netcat links</label>
                  <div
                    v-for="meta in localNetcatMetadata"
                    :key="meta.id"
                  >
                    <p>{{ meta.data }}</p>
                  </div>
                </div>
              </TabPanel>

              <TabPanel
                v-if="localWhois"
                value="3"
              >
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
                <br>

                <pre
                  v-if="localWhois.data"
                  class="whois"
                >{{
                  localWhois.data
                }}</pre>
                <pre
                  v-if="localWhois.rdap_string"
                  class="whois"
                >{{
                  localWhois.rdap_string
                }}</pre>
              </TabPanel>
              <TabPanel value="4">
                <div v-if="request.triage_payload">
                  <label class="label">Request payload</label>
                  <RawHttpCard
                    label="Triage Payload"
                    :data="request.triage_payload"
                  />
                </div>

                <table v-if="request.triaged == true">
                  <tbody>
                    <tr v-if="request.triage_payload_type">
                      <th>Triage Payload type</th>
                      <td>{{ request.triage_payload_type }}</td>
                    </tr>
                    <tr v-if="request.triage_has_payload">
                      <th>Triage Has Payload</th>
                      <td>{{ request.triage_has_payload }}</td>
                    </tr>
                    <tr v-if="request.triage_target_parameter">
                      <th>Triage Parameter</th>
                      <td>{{ request.triage_target_parameter }}</td>
                    </tr>
                  </tbody>
                </table>

                <div v-if="localDescription">
                  <table>
                    <tbody>
                      <tr>
                        <th>Review status</th>
                        <td>{{ localDescription.review_status }}</td>
                      </tr>
                      <tr>
                        <th>Source request ID</th>
                        <td>{{ localDescription.example_request_id }}</td>
                      </tr>
                      <tr v-if="localDescription.ai_application">
                        <th>Detected application</th>
                        <td>{{ localDescription.ai_application }}</td>
                      </tr>
                      <tr v-if="localDescription.ai_has_payload">
                        <th>Has payload</th>
                        <td>{{ localDescription.ai_has_payload }}</td>
                      </tr>
                      <tr v-if="localDescription.ai_cve">
                        <th>Guessed CVE</th>
                        <td>{{ localDescription.ai_cve }}</td>
                      </tr>

                      <tr v-if="localDescription.ai_mitre_attack">
                        <th>MITRE ATT&CK (experimental)</th>
                        <td>{{ localDescription.ai_mitre_attack }}</td>
                      </tr>

                      <tr v-if="localDescription.ai_targeted_parameter">
                        <th>Targeted parameter (experimental)</th>
                        <td>{{ localDescription.ai_targeted_parameter }}</td>
                      </tr>

                      <tr v-if="localDescription.ai_vulnerability_type">
                        <th>CWE</th>
                        <td>{{ localDescription.ai_vulnerability_type }}</td>
                      </tr>

                      <tr v-if="localDescription.ai_shell_commands">
                        <th>Shell commands (experimental)</th>
                        <td>{{ localDescription.ai_shell_commands }}</td>
                      </tr>

                      <tr v-if="localDescription.source_model">
                        <th>AI model</th>
                        <td>{{ localDescription.source_model }}</td>
                      </tr>
                    </tbody>
                  </table>
                </div>
              </TabPanel>
            </TabPanels>
          </PrimeTabs>
        </template>
      </InfoCard>
    </div>
  </div>
</template>

<script>
import RawHttpCard from "../cards/RawHttpCard.vue";
import RequestTable from "../cards/RequestDetailsTable.vue";
export default {
  components: { RawHttpCard, RequestTable },
  inject: ["config"],
  props: {
    "request": {
      type: Object,
      required: true
    },
    "metadata": {
      type: Object,
      required: true
    },
    "whois": {
      type: Object,
      required: true
    },
    "description":{
      type: Object,
      required: true
    }
  },
  emits: ["require-auth"],
  data() {
    return {
      localWhois: null,
      localDescription: null,
      localConclusion: null,
      localMetadata: [],
      localBase64Metadata: [],
      localLinkMetadata: [],
      localTCPMetadata: [],
      localPingMetadata: [],
      localNetcatMetadata: [],
      localUnicodeMetadata: [],
    };
  },
  watch: {
    whois() {
      if (this.whois == null) {
        this.localWhois = null;
      } else {
        this.localWhois = Object.assign({}, this.whois);
      }
    },
    description() {
      if (this.description == null) {
        this.localDescription = null;
        this.localConclusion = null;
      } else {
        this.localDescription = Object.assign({}, this.description);
        if (this.localDescription.ai_malicious == "") {
          this.localConclusion = "";
        } else {
          if (this.localDescription.ai_malicious == "yes") {
            if (
              this.localDescription.ai_vulnerability_type != "" &&
              this.localDescription.ai_vulnerability_type != "none"
            ) {
              this.localConclusion =
                'AI conclusion: this request is malicious and tries to exploit a "' +
                this.localDescription.ai_vulnerability_type +
                '" vulnerability type.';
            } else {
              this.localConclusion = "AI conclusion: this request is malicous.";
            }
          } else if (this.localDescription.ai_malicious == "no") {
            this.localConclusion =
              "AI conclusion: this request is not malicous";
          }
        }
      }
    },
    metadata() {
      this.localMetadata = [];
      this.localBase64Metadata = [];
      this.localLinkMetadata = [];
      this.localTCPMetadata = [];
      this.localPingMetadata = [];
      this.localNetcatMetadata = [];
      this.localUnicodeMetadata = [];
      for (var i = 0; i < this.metadata.length; i++) {
        if (this.metadata[i].type == "DECODED_STRING_BASE64") {
          this.localBase64Metadata.push(this.metadata[i]);
        } else if (this.metadata[i].type == "PAYLOAD_LINK") {
          this.localLinkMetadata.push(this.metadata[i]);
        } else if (this.metadata[i].type == "PAYLOAD_TCP_LINK") {
          this.localTCPMetadata.push(this.metadata[i]);
        } else if (this.metadata[i].type == "PAYLOAD_PING") {
          this.localPingMetadata.push(this.metadata[i]);
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
  methods: {
    toggleReviewOk(hash) {
      var newStatus = this.config.reviewStatusOk;
      if (this.localDescription.review_status == this.config.reviewStatusOk) {
        newStatus = this.config.reviewStatusNew;
      }
      this.updateReview(newStatus, hash);
      this.localDescription.review_status = newStatus;
    },
    toggleReviewNok(hash) {
      var newStatus = this.config.reviewStatusNok;
      if (this.localDescription.review_status == this.config.reviewStatusNok) {
        newStatus = this.config.reviewStatusNew;
      }
      this.updateReview(newStatus, hash);
      this.localDescription.review_status = newStatus;
    },
    updateReview(status, hash) {
      fetch(this.config.backendAddress + "/description/status", {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          "API-Key": this.$store.getters.apiToken,
        },
        body: "status=" + status + "&hash=" + hash,
      })
        .then((response) => {
          if (response.status == 403) {
            this.$emit("require-auth");
          } else {
            return response.json();
          }
        })
        .then((response) => {
          if (response.status == this.config.backendResultNotOk) {
            this.$toast.error(response.message);
          } else {
            this.$toast.success("Updated status");
          }
        });
    },
  },
};
</script>

<style scoped>
code.hljs {
  max-height: 400px;
  max-width: 100%;
  overflow: auto;
  border-radius: var(--p-border-radius);
}

table {
  border-collapse: collapse;
}

th,
td {
  padding: 0.25rem 0.75rem 0.25rem 0;
}
</style>
