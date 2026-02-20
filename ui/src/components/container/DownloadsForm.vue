<template>
  <div>
    <input
      v-model="localDownload.id"
      type="hidden"
      name="id"
    >
    <div>
      <InfoCard mylabel="Malware details">
        <template #default>
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
              <tr v-if="localDownload.content_type">
                <th>Content type</th>
                <td>{{ localDownload.content_type }}</td>
              </tr>
              <tr v-if="localDownload.detected_content_type">
                <th>Detected mime</th>
                <td>{{ localDownload.detected_content_type }}</td>
              </tr>
              <tr v-if="localDownload.request_id">
                <th>First RID</th>
                <td>
                  <a :href="config.requestsLink + '?q=id:' + localDownload.request_id">{{ localDownload.request_id }}</a>
                </td>
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
              <tr>
                <th>Download honeypot</th>
                <td>{{ localDownload.honeypot_ip }}</td>
              </tr>
              <tr>
                <th>Local file</th>
                <td>{{ localDownload.file_location }}</td>
              </tr>
              <tr v-if="localDownload.yara_scanned_unpacked == true">
                <th>Binary was packed</th>
                <td>Yes</td>
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
                  <input
                    ref="sha256sum"
                    :value="localDownload.sha256sum"
                    type="hidden"
                  >

                  {{ localDownload.parsed.sha256sum }}
                  <i
                    title="copy to clipboard"
                    class="pi pi-copy pointer"
                    @click="copyToClipboard()"
                  />
                </td>
              </tr>
            </tbody>
          </table>
        </template>
      </InfoCard>
    </div>
  </div>
  <div v-if="localDownload.vt_file_analysis_submitted">
    <InfoCard mylabel="VirusTotal details">
      <template #default>
        <div class="grid grid-cols-2 gap-4">
          <div>
            <h4 class="vt-section-title">Scan Results</h4>
            <table>
              <tbody>
                <tr>
                  <th>Malicious</th>
                  <td class="vt-malicious">
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
          <div v-if="localDownload.vt_file_analysis_result">
            <h4 class="vt-section-title">Scanner Samples</h4>
            <table>
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
      </template>
    </InfoCard>
  </div>

  <InfoCard mylabel="Context">
    <template #default>
      <PrimeTabs v-model:value="activeTab">
        <TabList>
          <PrimeTab value="0">
            HTTP Request
          </PrimeTab>
          <PrimeTab
            v-if="localYara"
            value="1"
          >
            Yara result
          </PrimeTab>
          <PrimeTab
            v-if="localWhois"
            value="2"
          >
            Whois
          </PrimeTab>
        </TabList>
        <TabPanels>
          <TabPanel
            v-if="localYara"
            value="1"
          >
            <div
              v-if="localDownload.yara_description"
              id="aisummary"
            >
              AI Summary: {{ localDownload.yara_description }}
            </div>
            <YaraCard :data="localYara" />
          </TabPanel>
          <TabPanel value="0">
            <RawHttpCard
              v-if="localDownload.raw_http_response"
              label="HTTP response headers"
              :data="localDownload.raw_http_response"
            />
          </TabPanel>
          <TabPanel
            v-if="localWhois"
            value="2"
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
        </TabPanels>
      </PrimeTabs>
    </template>
  </InfoCard>

  <InfoCard mylabel="Actions">
    <template #default>
      <PrimeButton
        icon="pi pi-check"
        label="Rescan Yara"
        class="p-button-sm p-button-outlined"
        @click="requireConfirmation($event)"
      />
    </template>
  </InfoCard>
  <ConfirmPopup />
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
  inject: ["config"],
  props: {
    "download": {
      type: Object,
      required: false
    },
    "whois": {
      type: Object,
      required: false
    }
  },
  emits: ["require-auth"],
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
  computed: {
    yaraLastScanDate() {
      if (this.localDownload) {
        return dateToString(this.localDownload.yara_last_scan);
      }
      return "unknown";
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
  created() {},
  methods: {
    requireConfirmation(event) {
      if (!this.localDownload.id) {
        return;
      }
      this.$confirm.require({
        target: event.currentTarget,
        message: "Rescan with yara rules ?",
        accept: () => {
          this.setDownloadToPending();
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
            this.$toast.success(
              "Download has been set to pending. Reload later."
            );
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
};
</script>

<style scoped>
#aisummary {
  padding: 0.75rem;
  margin-bottom: 0.75rem;
  background: var(--p-surface-50);
  border-radius: var(--p-border-radius);
  border-left: 3px solid var(--p-primary-400);
  font-size: 0.9rem;
  line-height: 1.5;
}

table th {
  padding-right: 0.75rem;
  width: 140px;
  white-space: nowrap;
}

table td {
  padding-right: 0.75rem;
}

.vt-section-title {
  font-size: 0.85rem;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.03em;
  color: var(--p-text-muted-color);
  margin: 0 0 0.5rem 0;
}

.vt-malicious {
  color: var(--p-red-500);
  font-weight: 600;
}
</style>
