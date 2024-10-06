<template>
  <div class="columns">
    <div class="column is-three-fifths" style="margin-left: 15px">
      <DataSearchBar ref="searchBar" :isloading="isLoading" @search="performNewSearch" modelname="download"></DataSearchBar>

      <table class="table is-hoverable" v-if="downloads.length > 0">
        <thead>
          <th>ID</th>
          <th title="ID of the first request">First RID</th>
          <th title="ID of the last request">Last RID</th>
          <th>Orig URL</th>
          <th>Content Type</th>
          <th>Times Seen</th>
          <th>Last seen</th>
          <th>Actions</th>
        </thead>
        <tbody>
          <tr
            v-for="dl in downloads"
            @click="setSelectedDownload(dl.id)"
            :key="dl.id"
            :class="isSelectedId == dl.id ? 'is-selected' : ''"
          >
            <td>{{ dl.id }}</td>
            <td>
              <a :href="'/requests?q=id:' + dl.request_id">{{
                dl.request_id
              }}</a>
            </td>
            <td v-if="dl.last_request_id">
              <a :href="'/requests?q=id:' + dl.last_request_id">{{
                dl.last_request_id
              }}</a>
            </td>
            <td v-else>
              <a :href="'/requests?q=id:' + dl.request_id">{{
                dl.request_id
              }}</a>
            </td>
            <td>{{ dl.original_url }}</td>
            <td>{{ dl.content_type }}</td>
            <td>{{ dl.times_seen }}</td>
            <td :title="'First seen on: ' + dl.parsed.created_at">
              {{ dl.parsed.last_seen_at }}
            </td>
            <td>
              <a
                v-if="dl.parsed.vt_url_analysis_id"
                target="_blank"
                title="view URL analysis on virustotal"
                :href="
                  'https://www.virustotal.com/gui/url/' +
                  dl.parsed.vt_url_analysis_id
                "
              >
                <i class="pi pi-bolt"></i>
              </a>

              <a
                v-if="dl.parsed.vt_file_analysis_id"
                target="_blank"
                title="view file analysis on virustotal"
                :href="
                  'https://www.virustotal.com/gui/file-analysis/' +
                  dl.parsed.vt_file_analysis_id
                "
              >
                <i class="pi pi-exclamation-triangle"></i>
              </a>
            </td>
          </tr>
        </tbody>
      </table>

      <i
        v-if="offset > 0"
        @click="loadPrev()"
        class="pi pi-arrow-left pi-style"
      ></i>
      <i
        v-if="downloads.length == limit"
        @click="loadNext()"
        class="pi pi-arrow-right pi-style pi-style-right"
      ></i>
    </div>
    <div
      class="column mright"
      @focusin="keyboardDisabled = true"
      @focusout="keyboardDisabled = false"
    >
      <downloads-form :whois="selectedWhois" :download="selectedDownload"></downloads-form>
    </div>
  </div>
</template>

<script>
function dateToString(inDate) {
  const nd = new Date(Date.parse(inDate));
  return nd.toLocaleString();
}
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
      offset: 0,
      keyboardDisabled: false,
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
    reloadDownloads() {
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
        this.loadWhois(selected.ip);
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
    setNextSelectedElement() {
      for (var i = 0; i < this.downloads.length; i++) {
        if (this.downloads[i].id == this.isSelectedId) {
          if (i + 1 < this.downloads.length) {
            this.setSelectedDownload(this.downloads[i + 1].id);
          } else {
            return false;
          }
          break;
        }
      }
      return true;
    },
    setPrevSelectedElement() {
      for (var i = this.downloads.length - 1; i >= 0; i--) {
        if (this.downloads[i].id == this.isSelectedId) {
          if (i - 1 >= 0) {
            this.setSelectedDownload(this.downloads[i - 1].id);
          } else {
            return false;
          }
          break;
        }
      }
      return true;
    },
    loadNext() {
      this.offset += this.limit;
      this.$router.push(this.getDownloadsLink());
      this.loadDownloads(true);
    },
    loadPrev() {
      if (this.offset - this.limit >= 0) {
        this.offset -= this.limit;
        this.$router.push(this.getDownloadsLink());
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
                  newDownload.sha256sum.substr(0, 16) + "...";

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
