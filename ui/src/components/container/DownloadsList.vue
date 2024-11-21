<template>
  <div class="columns">
    <div class="column is-three-fifths" style="margin-left: 15px">

      <div class="card">
        <DataTable
          :value="downloads"
          tableStyle="min-width: 50rem"
          :metaKeySelection="true"
          dataKey="id"
          showGridlines
          compareSelectionBy="equals"
          v-model:selection="selectedDownload"
          selectionMode="single"
        >
          <template #header>
            <DataSearchBar
              ref="searchBar"
              :isloading="isLoading"
              @search="performNewSearch"
              modelname="download"
            ></DataSearchBar>
          </template>
          <template #empty>No data matched. </template>
          <template #loading>Loading request data. Please wait. </template>

          <DataColumn field="id" header="ID" style="width: 4%">
          </DataColumn>
          <DataColumn header="First RID" style="width: 5%">
            <template #body="slotProps">
              <a :href="config.requestsLink + '?q=id:' + slotProps.data.request_id">{{ slotProps.data.request_id }}</a>
            </template>
          </DataColumn>
          <DataColumn header="Last RID" style="width: 5%">
            <template #body="slotProps">
              <a :href="config.requestsLink + '?q=id:' + slotProps.data.last_request_id">{{
                slotProps.data.last_request_id }}</a>
            </template>
          </DataColumn>
          <DataColumn field="parsed.original_url" header="Orig URL" style="width: 30%">
          </DataColumn>
          <DataColumn field="content_type" header="Content type" style="width: 15%">
          </DataColumn>
          <DataColumn field="times_seen" header="# seen" style="width: 6%">
          </DataColumn>
          <DataColumn field="parsed.last_seen_at" header="Last seen"
          style="width: 14%">
          </DataColumn>

          <DataColumn header="Actions" style="width: 10%">
            <template #body="slotProps">
              <a
                v-if="slotProps.data.parsed.vt_url_analysis_id"
                target="_blank"
                title="view URL analysis on virustotal"
                :href="
                  'https://www.virustotal.com/gui/url/' +
                  slotProps.data.parsed.vt_url_analysis_id
                "
              >
                <i class="pi pi-bolt"></i>
              </a>

              <a
                v-if="slotProps.data.parsed.vt_file_analysis_id"
                target="_blank"
                title="view file analysis on virustotal"
                :href="
                  'https://www.virustotal.com/gui/file-analysis/' +
                  slotProps.data.parsed.vt_file_analysis_id
                "
              >
                <i class="pi pi-exclamation-triangle"></i>
              </a>
            </template>
          </DataColumn>
          <template #footer>
            <div class="flex justify-between items-center">
            <div>
            <i
              v-if="offset > 0"
              @click="loadPrev()"
              class="pi pi-arrow-left pi-style"
            ></i>
            <i
              v-if="offset == 0"
              class="pi pi-arrow-left pi-style-disabled"
            ></i>
            </div>
            <div>

            <FormSelect v-model="selectedLimit" :options="limitOptions" placeholder="Limit" editable checkmark :highlightOnSelect="false" class="w-full md:w-56" />
            </div>
            <div>
            <i
              v-if="downloads.length == limit"
              @click="loadNext()"
              class="pi pi-arrow-right pi-style pi-style-right"
            ></i>
            </div>
            </div>
          </template>

        </DataTable>
      </div>
    </div>
    <div
      class="column mright"
    >

      <downloads-form :whois="selectedWhois" :download="selectedDownload"></downloads-form>
    </div>
  </div>
</template>

<script>
import { dateToString } from './../../helpers.js';
import DownloadsForm from "./DownloadsForm.vue";
import DataSearchBar from "../DataSearchBar.vue";
export default {
  components: {
    DownloadsForm,
    DataSearchBar,
  },
  inject: ["config"],
  emits: ["require-auth"],
  data() {
    return {
      downloads: [],
      selectedDownload: null,
      selectedWhois: null,
      isSelectedId: 0,
      query: null,
      limit: 24,
      selectedLimit: 21,
      limitOptions: [10, 20, 30, 40, 50],
      offset: 0,
      isLoading: false,
      baseDownload: {
        id: 0,
        request_id: 0,
        original_url: "",
        content_type: "",
        parsed: {
          created_at: "",
        },
      },
    };
  },
  methods: {
    performNewSearch(query) {
      this.query = query;
      this.offset = 0;
      this.loadDownloads(true);
    },
    setSelectedDownload(id) {
      var selected = null;
      for (var i = 0; i < this.downloads.length; i++) {
        if (this.downloads[i].id == id) {
          selected = this.downloads[i];
          break;
        }
      }
      if (selected == null) {
        console.log("error: could not find ID: " + id);
      } else {
        this.selectedDownload = selected;
        this.isSelectedId = id;
      }
    },
    getFreshDownloadLink() {
      return this.config.downloadsLink + "/0/" + this.limit;
    },
    getDownloadsLink() {
      let link =
        this.config.downloadsLink + "/" + this.offset + "/" + this.limit;
      if (this.query) {
        link += "?q=" + this.query;
      }

      return link;
    },
    loadNext() {
      this.offset += this.limit;
      this.loadDownloads(true);
    },
    loadPrev() {
      if (this.offset - this.limit >= 0) {
        this.offset -= this.limit;
        this.loadDownloads(false);
      }
    },
    loadWhois(ip) {
      fetch(this.config.backendAddress + "/whois/ip", {
        method: "POST",
        headers: {
          "API-Key": this.$store.getters.apiToken,
          "Content-Type": "application/x-www-form-urlencoded",
        },
        body: "ip=" + ip,
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
            this.selectedWhois = null;
          } else {
            if (response.data) {
              this.selectedWhois = response.data;
            } else {
              this.selectedWhois = null;
            }
          }
        });
    },
    loadDownloads(selectFirst) {

      this.isLoading = true;
      var url =
        this.config.backendAddress +
        "/downloads/segment?offset=" +
        this.offset +
        "&limit=" +
        this.limit;
      if (this.query) {
        url += "&q=" + encodeURIComponent(this.query);
      }
      fetch(url, {
        headers: {
          "API-Key": this.$store.getters.apiToken,
        },
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
            this.isLoading = false;
            return;
          }
          if (response.status == this.config.backendResultNotOk) {
            this.$toast.error(response.message);
          } else {
            this.downloads = [];
            if (response.data) {
              for (var i = 0; i < response.data.length; i++) {
                const newDownload = Object.assign({}, response.data[i]);
                newDownload.parsed = {};
                newDownload.parsed.created_at = dateToString(
                  newDownload.created_at
                );
                newDownload.parsed.last_seen_at = dateToString(
                  newDownload.last_seen_at
                );

                newDownload.parsed.sha256sum =
                  newDownload.sha256sum.slice(0, 16) + "...";


                if (newDownload.original_url.length > 70) {
                  newDownload.parsed.original_url =
                    newDownload.original_url.slice(0, 70) + "...";
                } else {
                  newDownload.parsed.original_url = newDownload.original_url;
                }

                if (newDownload.vt_url_analysis_id) {
                  var parts = newDownload.vt_url_analysis_id.split("-");
                  if (parts.length != 3) {
                    console.log(
                      "Cannot parse ID: " + newDownload.vt_url_analysis_id
                    );
                  } else {
                    newDownload.parsed.vt_url_analysis_id = parts[1];
                  }
                }

                if (newDownload.vt_file_analysis_id) {
                  newDownload.parsed.vt_file_analysis_id = newDownload.vt_file_analysis_id;
                }

                if (newDownload.vt_file_analysis_done && newDownload.vt_file_analysis_result) {
                  newDownload.parsed.vt_file_analysis_result = [];
                  newDownload.vt_file_analysis_result.forEach((re) => {
                    var eparts = re.split(/:(.*)/s)
                    newDownload.parsed.vt_file_analysis_result.push(
                      {
                        engine: eparts[0],
                        result: eparts[1],
                      }
                    )
                  })
                }

                this.downloads.push(newDownload);
              }

              if (selectFirst) {
                this.setSelectedDownload(response.data[0].id);
              } else {
                this.setSelectedDownload(
                  response.data[response.data.length - 1].id
                );
              }
            }
          }
          this.isLoading = false;
        });
    },
  },
  watch: {
    selectedLimit() {
      this.limit = this.selectedLimit;
      this.loadDownloads(true);
    },
    selectedDownload() {
      this.loadWhois(this.selectedDownload.ip);
    }
  },
  beforeCreate() {
    this.selectedDownload = this.baseDownload;
  },
  created() {
    if (this.$route.params.limit) {
      this.limit = parseInt(this.$route.params.limit);
    }

    if (this.$route.params.offset) {
      this.offset = parseInt(this.$route.params.offset);
    }

    this.selectedLimit = this.limit;
  },
  mounted() {
    if (this.$route.query.q) {
      this.query = this.$route.query.q;
      this.$refs.searchBar.setQuery(this.$route.query.q);
    }
    this.loadDownloads(true);
  },
};
</script>

<style scoped>
#date {
  width: 170px;
}
.table tr.is-selected {
  background-color: #4e726d;
}
table {
  width: 100%;
}

td {
  font-size: 13px;
}

i.pi-style {
  font-size: 2rem;
  color: #00d1b2;
}

i.pi-style-right {
  float: right;
}

.p-inputtext {
  width: 100%;
}
</style>
