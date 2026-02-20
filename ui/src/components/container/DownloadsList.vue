<template>
  <div class="list-layout">
    <div class="list-table-wrap">
        <DataTable
          v-model:selection="selectedDownload"
          :value="downloads"
          table-style="min-width: 50rem"
          :meta-key-selection="true"
          data-key="id"
          show-gridlines
          compare-selection-by="equals"
          selection-mode="single"
        >
          <template #header>
            <DataSearchBar
              ref="searchBar"
              :isloading="isLoading"
              modelname="download"
              @search="performNewSearch"
            />
          </template>
          <template #empty>
            No data matched.
          </template>
          <template #loading>
            Loading request data. Please wait.
          </template>

          <DataColumn
            field="id"
            header="ID"
            style="width: 4%"
          />
          <DataColumn
            header="Last RID"
            style="width: 5%"
          >
            <template #body="slotProps">
              <a :href="config.requestsLink + '?q=id:' + slotProps.data.last_request_id">{{
                slotProps.data.last_request_id }}</a>
            </template>
          </DataColumn>
          <DataColumn
            field="parsed.original_url"
            header="Orig URL"
          />
          <DataColumn
            field="times_seen"
            header="# seen"
            class="col-shrink"
          />
          <DataColumn
            field="parsed.last_seen_at"
            header="Last seen"
            class="col-shrink"
          />

          <DataColumn
            header="Actions"
            class="col-shrink"
          >
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
                <i class="pi pi-bolt" />
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
                <i class="pi pi-exclamation-triangle" />
              </a>
            </template>
          </DataColumn>
          <template #footer>
            <div class="flex justify-between items-center">
              <div>
                <i
                  v-if="offset > 0"
                  class="pi pi-arrow-left pi-style"
                  @click="loadPrev()"
                />
                <i
                  v-if="offset == 0"
                  class="pi pi-arrow-left pi-style-disabled"
                />
              </div>
              <div>
                <FormSelect
                  v-model="selectedLimit"
                  :options="limitOptions"
                  placeholder="Limit"
                  editable
                  checkmark
                  :highlight-on-select="false"
                  class="w-full md:w-56"
                  @change="onChangeLimit()"
                />
              </div>
              <div>
                <i
                  v-if="downloads.length == limit"
                  class="pi pi-arrow-right pi-style pi-style-right"
                  @click="loadNext()"
                />
              </div>
            </div>
          </template>
        </DataTable>
    </div>
    <div class="list-form-wrap">
      <downloads-form
        :whois="selectedWhois"
        :download="selectedDownload"
      />
    </div>
  </div>
</template>

<script>
import { dateToString, sharedMixin } from './../../helpers.js';
import DownloadsForm from "./DownloadsForm.vue";
import DataSearchBar from "../DataSearchBar.vue";
export default {
  components: {
    DownloadsForm,
    DataSearchBar,
  },
  mixins: [sharedMixin],
  inject: ["config"],
  emits: ["require-auth"],
  data() {
    return {
      downloads: [],
      selectedDownload: null,
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
  watch: {
    selectedDownload() {
      this.loadWhois(this.selectedDownload.ip);
    }
  },
  beforeCreate() {
    this.selectedDownload = this.baseDownload;
  },
  mounted() {
    if (this.$route.query.q) {
      this.query = this.$route.query.q;
      this.$refs.searchBar.setQuery(this.$route.query.q);
    }

    if (this.$route.params.limit) {
      this.limit = parseInt(this.$route.params.limit);
    }

    if (this.$route.params.offset) {
      this.offset = parseInt(this.$route.params.offset);
    }

    // Note that setting selectedLimit also causes the data to be loaded.
    this.selectedLimit = this.limit;

    this.loadDownloads(true);
  },
  methods: {
    onChangeLimit() {
      this.limit = this.selectedLimit
      this.loadDownloads(true);
    },

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

};
</script>

<style scoped>
.p-inputtext {
  width: 100%;
}
</style>
