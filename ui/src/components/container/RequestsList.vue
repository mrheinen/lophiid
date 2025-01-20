<template>
  <div class="columns">
    <div class="column is-three-fifths" style="margin-left: 15px">
      <div class="card">
        <DataTable
          :value="requests"
          tableStyle="min-width: 50rem"
          :metaKeySelection="true"
          dataKey="id"
          showGridlines
          compareSelectionBy="equals"
          v-model:selection="selectedRequest"
          selectionMode="single"
        >
          <template #header>
            <DataSearchBar
              ref="searchBar"
              :isloading="isLoading"
              @search="performNewSearch"
              modelname="request"
            ></DataSearchBar>
          </template>
          <template #empty>No data matched. </template>
          <template #loading>Loading request data. Please wait. </template>
          <DataColumn field="parsed.received_at" header="Date" style="width: 15%"
          >
          </DataColumn>

          <DataColumn field="honeypot_ip" header="Honeypot" style="width: 10%">
          </DataColumn>
          <DataColumn field="method" header="Method" style="width: 5%">
          </DataColumn>
          <DataColumn field="parsed.uri" header="URI">
          </DataColumn>
          <DataColumn field="source_ip" header="Source" style="width: 10%">
            <template #body="slotProps">
              <a
                :href="
                  getFreshRequestLink() +
                  '?q=source_ip:' +
                  slotProps.data.source_ip
                "
              >
                {{ slotProps.data.source_ip }}</a
              >
            </template>
          </DataColumn>
          <DataColumn header="Actions" style="width: 5%">
            <template #body="slotProps">
              <a
                :href="
                  config.rulesLink + '?uri=' +
                  encodeURIComponent(slotProps.data.uri) +
                  '&method=' +
                  slotProps.data.method
                "
              >
                <i
                  title="create a rule for this"
                  class="pi pi-arrow-circle-right"
                ></i>
              </a>
              &nbsp;
              <i
                @click="toggleStarred(slotProps.data.id)"
                :class="slotProps.data.starred ? 'starred' : ''"
                title="Star this request"
                class="pi pi-star pointer"
              ></i>
            </template>
          </DataColumn>
          <template #footer>

            <div class="flex justify-between items-center">
            <div>
            <i
              v-if="offset > 0"
              @click="loadPrevRequests()"
              class="pi pi-arrow-left pi-style"
            ></i>
            <i
              v-if="offset == 0"
              class="pi pi-arrow-left pi-style-disabled"
            ></i>
            </div>
            <div>

            <FormSelect v-model="selectedLimit" @change="onChangeLimit" :options="limitOptions" placeholder="Limit" editable checkmark :highlightOnSelect="false" class="w-full md:w-56" />
            </div>
            <div>
            <i
              v-if="requests.length == limit"
              @click="loadNextRequests()"
              class="pi pi-arrow-right pi-style pi-style-right"
            ></i>
            </div>
            </div>
          </template>
        </DataTable>
      </div>
    </div>
    <div class="column restricted-width mright">
      <request-view v-if="selectedRequest"
        :request="selectedRequest"
        :metadata="selectedMetadata"
        :whois="selectedWhois"
        :description="selectedDescription"
      ></request-view>
    </div>
  </div>
</template>

<script>
import { dateToString } from './../../helpers.js';
import RequestView from "./RequestView.vue";
import DataSearchBar from "../DataSearchBar.vue";
export default {
  components: {
    RequestView,
    DataSearchBar,
  },
  emits: ["require-auth"],
  inject: ["config"],
  data() {
    return {
      searchIsFocused: false,
      requests: [],
      limit: 21,
      selectedRequest: null,
      selectedMetadata: [],
      selectedWhois: null,
      selectedDescription: null,
      displayRequest: {},
      selectedLimit: 21,
      limitOptions: [10, 20, 30, 40, 50],
      query: null,
      isSelectedElement: null,
      isSelectedId: 0,
      isLoading: false,
      offset: 0,
    };
  },
  methods: {
    onChangeLimit() {
      this.limit = this.selectedLimit
      this.loadRequests(true);
    },
    showPopover(event) {
      this.$refs.spop.show(event);
    },
    toggleStarred(id) {
      var starRequest = null;
      for (var i = 0; i < this.requests.length; i++) {
        if (this.requests[i].id == id) {
          starRequest = this.requests[i];
          break;
        }
      }

      if (starRequest == null) {
        console.log("Could not find request with ID: " + id);
        return;
      }

      starRequest.starred = !starRequest.starred;
      // Copy it so that when we delete the "parsed" section it does not mess up
      // the UI.
      var copyRequest = Object.assign({}, starRequest);

      delete copyRequest.parsed;
      fetch(this.config.backendAddress + "/request/update", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "API-Key": this.$store.getters.apiToken,
        },
        body: JSON.stringify(copyRequest),
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
            this.$toast.success("Updated request");
          }
        });
    },
    performNewSearch(query) {
      this.query = query;
      this.offset = 0;
      this.loadRequests(true);
    },
    reloadRequests() {
      this.loadRequests(true);
    },
    getRequestLink() {
      let link =
        this.config.requestsLink + "/" + this.offset + "/" + this.limit;
      if (this.query) {
        link += "?q=" + encodeURIComponent(this.query);
      }

      console.log(link);
      return link;
    },
    getFreshRequestLink() {
      return this.config.requestsLink + "/0/" + this.limit;
    },
    lazyLoad(event) {
      console.log(event);

      if (event.last == 0) {
        event.last = 40;
      }

      this.offset = event.first;
      this.limit = event.last;
      this.loadNextRequests();
    },
    loadNextRequests() {
      if (this.requests.length > 0) {
        this.offset += this.limit;
      }
      this.loadRequests(true);
    },
    loadPrevRequests() {
      if (this.offset - this.limit >= 0) {
        this.offset -= this.limit;
        this.loadRequests(false);
      }
    },
    setSelectedReq(id) {
      var selected = null;
      this.selectedMetadata = [];
      this.loadMetadata(id);

      for (var i = 0; i < this.requests.length; i++) {
        if (this.requests[i].id == id) {
          selected = this.requests[i];
          break;
        }
      }

      if (selected == null) {
        console.log("error: could not find ID: " + id);
      } else {
        this.selectedRequest = selected;
        this.loadWhois(selected.source_ip);
        this.loadDescription(selected.cmp_hash);
        this.isSelectedId = id;
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
    loadDescription(cmpHash) {
      if (cmpHash == "") {
        this.selectedDescription = null;
        return;
      }
      fetch(this.config.backendAddress + "/description/single", {
        method: "POST",
        headers: {
          "API-Key": this.$store.getters.apiToken,
          "Content-Type": "application/x-www-form-urlencoded",
        },
        body: "cmp_hash=" + cmpHash,
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
            this.selectedDescription = null;
          } else {
            if (response.data) {
              this.selectedDescription = response.data;
            } else {
              this.selectedDescription = null;
            }
          }
        });
    },


    loadMetadata(id) {
      fetch(this.config.backendAddress + "/meta/request", {
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
              this.selectedMetadata = response.data;
            }
          }
        });
    },
    loadRequests(selectFirst) {
      // Start the spinner
      this.isLoading = true;

      var url =
        this.config.backendAddress +
        "/request/segment?offset=" +
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
            this.isLoading = false;
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
            this.requests = [];
            if (!response.data) {
              this.$toast.info("No data found");
              this.isLoading = false;
              return;
            }
            for (var i = 0; i < response.data.length; i++) {
              const newReq = Object.assign({}, response.data[i]);
              newReq.parsed = {};
              newReq.parsed.created_at = dateToString(newReq.created_at);
              newReq.parsed.updated_at = dateToString(newReq.updated_at);
              newReq.parsed.received_at = dateToString(newReq.time_received);
              var maxUriLength = 75;
              if (newReq.uri.length > maxUriLength) {
                newReq.parsed.uri =
                  newReq.uri.slice(0, maxUriLength) + "...";
              } else {
                newReq.parsed.uri = newReq.uri;
              }
              newReq.parsed.body = atob(newReq.body);
              this.requests.push(newReq);
            }
            if (selectFirst) {
              this.setSelectedReq(response.data[0].id);
            } else {
              this.setSelectedReq(response.data[response.data.length - 1].id);
            }
          }
          this.isLoading = false;
        });
    },
  },
  watch: {
    selectedRequest() {
      this.loadDescription(this.selectedRequest.cmp_hash);
      this.loadWhois(this.selectedRequest.source_ip);
    },
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
    this.loadRequests(true);
  },
};
</script>

<style>
.mytag {
  font-size: 0.65rem;
  display: inline-block;
  background-color: #d7e7dc;
  padding-right: 3px;
  padding-left: 3px;
  border-radius: 5px;
  margin-left: 10px;
}
.date {
  width: 170px;
  white-space: nowrap;
}

.method {
  white-space: nowrap;
}

.honeypot {
  width: 140px;
}

.sourceip {
  width: 100px;
}

.uri {
  width: 80%;
}

.pointer {
  cursor: pointer;
}

table {
  width: 100%;
}

.p-datatable-tbody > tr > td {
  padding-top: 5px !important;
  padding-bottom: 5px !important;
  padding-left: 13px !important;
  padding-right: 13px !important;
}
#p-datatable-table tr {
  font-size: 12px;
}
span.search-info-icon {
  color: black;
}

span.search-info-icon:hover {
  color: black;
  font-weight: bold !important;
}

i.pi-style {
  font-size: 2rem;
  color: #00d1b2;
}

i.pi-style-disabled {
  font-size: 2rem;
  color: #616060;
}

i.pi-style-right {
  float: right;
}

.restricted-width {
  width: 700px;
}

.p-inputtext {
  width: 100%;
}

.starred {
  color: red;
}

input.p-select-label {
  width: 40px;
}
.justify-between {
  justify-content: space-between;
}

.items-center {
  align-items: center;
}
.flex {
  display: flex;
}
</style>
