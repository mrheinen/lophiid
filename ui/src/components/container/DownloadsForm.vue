<template>
  <div>
    <input type="hidden" name="id" v-model="localDownload.id" />
      <FieldSet legend="Download details" :toggleable="false">
        <table>
          <tbody>
            <tr>
              <th>First seen</th>
              <td>{{ localDownload.parsed.created_at }}</td>
            </tr>
            <tr>
              <th>Last seen</th>
              <td>{{ localDownload.parsed.last_seen_at }}</td>
            </tr>
            <tr>
              <th>Times seen</th>
              <td>{{ localDownload.times_seen }}</td>
            </tr>
            <tr>
              <th>Size byte</th>
              <td>{{ localDownload.size }}</td>
            </tr>
            <tr v-if="localDownload.detected_content_type">
              <th>Detected mime</th>
              <td>{{ localDownload.detected_content_type }}</td>
            </tr>
            <tr>
              <th>URL Original</th>
              <td>{{ localDownload.original_url }}</td>
            </tr>
            <tr v-if="localDownload.original_url != localDownload.used_url">
              <th>URL Used</th>
              <td>
                {{ localDownload.used_url }} (Host: {{ localDownload.host }})
              </td>
            </tr>
            <tr v-if="localDownload.yara_scanned_unpacked == true">
              <th>Binary was packed</th>
              <td>
                Yes
              </td>
            </tr>
            <tr v-if="localDownload.yara_status">
              <th>Yara status</th>
              <td>
                {{ localDownload.yara_status }}
              </td>
            </tr>
            <tr v-if="localDownload.yara_last_scan">
              <th>Yara last scan</th>
              <td>
                {{ yaraLastScanDate }}
              </td>
            </tr>



            <tr>

              <th>SHA 256</th>
              <td>
                <input :value="localDownload.sha256sum" ref="sha256sum" type="hidden" />

                {{ localDownload.parsed.sha256sum }}
                <i
                  @click="copyToClipboard()"
                  title="copy to clipboard"
                  class="pi pi-copy pointer"
                ></i>
              </td>
            </tr>
          </tbody>
        </table>
      </FieldSet>
    </div>
    <br />
    <div v-if="localDownload.vt_file_analysis_submitted">
      <FieldSet legend="VirusTotal results" :toggleable="false">
        <div>
          <div style="margin: 0 auto;">
            <div style="float: left;">
              Scan results
              <br/>
              <table class="slightlylow">
                <tbody>
                  <tr>
                    <th>Malicious</th>
                    <td style="color: red">
                      {{ localDownload.vt_analysis_malicious }}
                    </td>
                  </tr>
                  <tr>
                    <th>Harmless</th>
                    <td>
                      {{ localDownload.vt_analysis_harmless }}
                    </td>
                  </tr>
                  <tr>
                    <th>Suspicious</th>
                    <td>
                      {{ localDownload.vt_analysis_suspicious }}
                    </td>
                  </tr>
                  <tr>
                    <th>Undetected</th>
                    <td>
                      {{ localDownload.vt_analysis_undetected }}
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>
            <div style="margin-left: 200px;">
              Scanner samples
              <br/>
              <table v-if="localDownload.vt_file_analysis_result" class="slightlylow">
                <tbody>
                  <tr
                    v-for="res in localDownload.parsed.vt_file_analysis_result"
                    :key="res"
                  >
                    <th>{{ res.engine }}</th>
                    <td>{{ res.result }}</td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>
        </div>
      </FieldSet>
    </div>

    <br />

    <FieldSet legend="Context" :toggleable="false">
    <PrimeTabs v-model:value="activeTab">
    <TabList>
        <PrimeTab value="0">HTTP Request</PrimeTab>
        <PrimeTab value="1" v-if="localYara">Yara result</PrimeTab>
        <PrimeTab value="2" v-if="localWhois">Whois</PrimeTab>
    </TabList>
        <TabPanels>
        <TabPanel value="1" v-if="localYara">
          <YaraCard :data="localYara">
          </YaraCard>
        </TabPanel>
        <TabPanel value="0">
          <RawHttpCard
            v-if="localDownload.raw_http_response"
            label="HTTP response headers"
            :data="localDownload.raw_http_response"
          ></RawHttpCard>
        </TabPanel>
        <TabPanel value="2" v-if="localWhois">
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
    </TabPanels>
    </PrimeTabs>
    </FieldSet>

    <FieldSet legend="Actions" :toggleable="false">
          <PrimeButton
            icon="pi pi-check"
            label="Rescan Yara"
            @click="requireConfirmation($event)"
            class="p-button-sm p-button-outlined">
          </PrimeButton>

    </FieldSet>
  <ConfirmPopup group="headless">
    <template #container="{ message, acceptCallback, rejectCallback }">
      <div class="bg-gray-900 text-white border-round p-3">
        <span>{{ message.message }}</span>
        <div class="flex align-items-center gap-2 mt-3">
          <PrimeButton
            icon="pi pi-check"
            label="Yes please!"
            @click="acceptCallback"
            class="p-button-sm p-button-outlined"
          ></PrimeButton>
          <PrimeButton
            label="Cancel"
            severity="secondary"
            outlined
            @click="rejectCallback"
            class="p-button-sm p-button-text"
          ></PrimeButton>
        </div>
      </div>
    </template>
  </ConfirmPopup>



</template>

<script>
import { dateToString, copyToClipboardHelper } from "../../helpers.js";
import RawHttpCard from "../cards/RawHttpCard.vue";
import YaraCard from "../cards/YaraCard.vue";

export default {
  components: {
    RawHttpCard,
    YaraCard,
  },
  props: ["download", "whois"],
  emits: ["require-auth"],
  inject: ["config"],
  data() {
    return {
      localWhois: null,
      localYara: null,
      activeTab: "0",
      localDownload: {
        parsed: {},
      },
    };
  },
  methods: {

    requireConfirmation(event) {
      if (!this.localDownload.id) {
        return;
      }
      this.$confirm.require({
        target: event.currentTarget,
        group: "headless",
        message: "Rescan with yara rules ?",
        accept: () => {
          this.setDownloadToPending()
        },
        reject: () => {},
      });
    },
    copyToClipboard() {
      copyToClipboardHelper(this.$refs.sha256sum.value);
      this.$toast.info("Copied");
    },
    setDownloadToPending() {
      this.localDownload.yara_status = this.config.downloadYaraStatusPending;
      this.updateDownload();
    },
    updateDownload() {
      const downloadToSubmit = Object.assign({}, this.localDownload);
      // Remove the added fields.
      delete downloadToSubmit.parsed;

      fetch(this.config.backendAddress + "/downloads/update", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "API-Key": this.$store.getters.apiToken,
        },
        body: JSON.stringify(downloadToSubmit),
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
            this.$toast.success("Download has been set to pending. Reload later.");
          }
        });
    },
    loadYaraForDownload(id) {
      fetch(this.config.backendAddress + "/yara/bydownloadid", {
        method: "POST",
        headers: {
          "API-Key": this.$store.getters.apiToken,
          "Content-Type": "application/x-www-form-urlencoded",
        },
        body: "id=" + id,
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
            if (response.data) {
              this.localYara = response.data;
              this.activeTab = "1";
            }
          }
        });
    },
    exportDownload(id) {
      fetch(this.config.backendAddress + "/download/export", {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          "API-Key": this.$store.getters.apiToken,
        },
        body: "id=" + id,
      })
        .then((response) => {
          if (response.status == 403) {
            this.$emit("require-auth");
            return null;
          } else {
            return response.json();
          }
        })
        .then((response) => {
          if (!response) {
            return;
          }
          if (response.status == this.config.backendResultNotOk) {
            this.$toast.error("Could not export download");
          } else {
            var filename = "changeme.txt";
            const blob = new Blob([JSON.stringify(response.data)], {
              type: "application/binary",
            });
            const link = document.createElement("a");
            link.href = URL.createObjectURL(blob);
            link.download = filename;
            link.click();
            URL.revokeObjectURL(link.href);
            link.remove();
            this.$toast.success("Exported download");
          }
        });
    },
  },
  watch: {
    download() {
      this.localDownload = Object.assign({}, this.download);
      this.activeTab = "0";
      this.localYara = null;
      this.loadYaraForDownload(this.download.id);
    },
    whois() {
      if (this.whois == null) {
        this.localWhois = null;
      } else {
        this.localWhois = Object.assign({}, this.whois);
      }
    },
  },
  computed: {
    yaraLastScanDate() {
      if (this.localDownload) {
        return dateToString(this.localDownload.yara_last_scan);
      }
      return "unknown";
    },
  },
  created() {},
};
</script>

<style>
.p-fieldset-legend {
  width: 100% !important;
}

legend > a {
  float: left;
  padding: 0.75rem;
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

.slightlylow {
  margin-top: 10px;
}

.app {
  width: 100%;
  height: 400px;
}

.description {
  width: 100%;
  height: 140px;
}

.pointer {
  cursor: pointer;
}

table th {
  padding-right: 13px;
  width: 140px;
}
table td {
  padding-right: 13px;
}

</style>
