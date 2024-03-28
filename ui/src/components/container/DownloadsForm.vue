<template>
  <div>
    <input type="hidden" name="id" v-model="localDownload.id" />
    <div class="card">
      <FieldSet legend="Download details" :toggleable="true">
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
              <input
                :value="localDownload.sha256sum"
                ref="sha256sum"
                type="hidden"
              />
              <th>SHA 256</th>
              <td>
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
    <br/>
    <div v-if="localDownload.vt_file_analysis_submitted" class="card">
      <FieldSet legend="VirusTotal results" :toggleable="true">
        <div>
          <label class="label">Virus total results</label>
          <table class="slightlyright">
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

          <div v-if="localDownload.vt_file_analysis_result">
            <label class="label">Virus total result sample</label>
            <table class="slightlyright">
              <tbody>
                <tr v-for="res in localDownload.parsed.vt_file_analysis_result" :key="res">
                  <th>{{ res.engine }}</th>
                  <td>{{ res.result }}</td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
       </FieldSet>
      </div>

  <br/>
    <RawHttpCard v-if="localDownload.raw_http_response" label="HTTP response headers" :data="localDownload.raw_http_response"></RawHttpCard>
    <br/>
      <div v-if="localWhois" class="card">
         <FieldSet legend="WHOIS record" :toggleable="true">
            <pre class="whois">{{ localWhois.data }}</pre>
          </FieldSet>
       </div>


  </div>
</template>

<script>
import { copyToClipboardHelper } from "../../helpers.js";
import RawHttpCard from '../cards/RawHttpCard.vue';

export default {
  components: {
    RawHttpCard
  },
  props: ["download", "whois"],
  emits: ["require-auth"],
  inject: ["config"],
  data() {
    return {
      localWhois: null,
      localDownload: {
        parsed: {},
      },
    };
  },
  methods: {
    copyToClipboard() {
      copyToClipboardHelper(this.$refs.sha256sum.value);
      this.$toast.info("Copied");
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

.slightlyright {
  margin-left: 15px;
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

th {
  padding-right: 10px;
}
</style>
