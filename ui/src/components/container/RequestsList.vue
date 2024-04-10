<template>
  <div class="columns">
    <div class="column is-three-fifths" style="margin-left: 15px">
      <form @submit.prevent="performNewSearch()">
        <span class="p-input-icon-left" style="width: 100%">
          <i class="pi pi-search" />
          <InputText
            @focusin="searchIsFocused = true"
            @focusout="searchIsFocused = false"
            v-model="query"
            placeholder="Search"
          />
        </span>
      </form>

      <table class="table is-hoverable" v-if="requests.length > 0">
        <thead>
          <th>Date</th>
          <th>Honeypot</th>
          <th>Method</th>
          <th>Uri</th>
          <th>Src Host</th>
          <th>Actions</th>
        </thead>
        <tbody>
          <tr
            v-for="req in requests"
            @click="setSelectedReq(req.id)"
            :key="req.id"
            :class="isSelectedId == req.id ? 'is-selected' : ''"
          >
            <td class="date">{{ req.parsed.received_at }}</td>
            <td class="honeypot">{{ req.honeypot_ip }}:{{ req.port }}</td>
            <td class="method" v-if="req.method == 'POST'">
              {{ req.method }} ({{ req.content_length }})
            </td>
            <td class="method" v-else>{{ req.method }}</td>
            <td class="uri">
              <div>
                <div style="float: left">
                  {{ req.parsed.uri }}
                </div>
                <div style="float: left">
                  <div>
                    <div v-for="t in req.tags" :key="t.tag.id" :title="t.tag.description" class="mytag">
                      <a :href="'/requests?q=label:' + t.tag.name">{{ t.tag.name }}</a>
                    </div>
                  </div>
                </div>
              </div>
            </td>
            <td class="sourceip">
              <a
                :href="getFreshRequestLink() + '?q=source_ip:' + req.source_ip"
              >
                {{ req.source_ip }}</a
              >
            </td>
            <td>
              <a
                :href="
                  '/rules?uri=' +
                  encodeURIComponent(req.uri) +
                  '&method=' +
                  req.method
                "
              >
                <i
                  title="create a rule for this"
                  class="pi pi-arrow-circle-right"
                ></i>
              </a>
              &nbsp;
              <i
                @click="toggleStarred(req.id)"
                :class="req.starred ? 'starred' : ''"
                title="Star this request"
                class="pi pi-star pointer"
              ></i>
            </td>
          </tr>
        </tbody>
      </table>

      <i
        v-if="offset > 0"
        @click="loadPrevRequests()"
        class="pi pi-arrow-left pi-style"
      ></i>
      <i
        v-if="requests.length == limit"
        @click="loadNextRequests()"
        class="pi pi-arrow-right pi-style pi-style-right"
      ></i>
    </div>
    <div class="column restricted-width mright">
      <request-view
        :request="selectedRequest"
        :metadata="selectedMetadata"
        :whois="selectedWhois"
      ></request-view>
    </div>
  </div>
</template>

<script>
function dateToString(inDate) {
  const nd = new Date(Date.parse(inDate));
  return nd.toLocaleString();
}
import RequestView from "./RequestView.vue";
export default {
  components: {
    RequestView,
  },
  emits: ["require-auth"],
  inject: ["config"],
  data() {
    return {
      searchIsFocused: false,
      requests: [],
      selectedRequest: null,
      selectedMetadata: [],
      selectedWhois: null,
      query: null,
      isSelectedElement: null,
      isSelectedId: 0,
      limit: 24,
      offset: 0,
    };
  },
  methods: {
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
    performNewSearch() {
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
        link += "?q=" + this.query;
      }

      return link;
    },
    getFreshRequestLink() {
      return this.config.requestsLink + "/0/" + this.limit;
    },
    loadNextRequests() {
      this.offset += this.limit;
      this.$router.push(this.getRequestLink());
      this.loadRequests(true);
    },
    loadPrevRequests() {
      if (this.offset - this.limit >= 0) {
        this.offset -= this.limit;
        this.$router.push(this.getRequestLink());
        this.loadRequests(false);
      }
    },
    setNextSelectedElement() {
      for (var i = 0; i < this.requests.length; i++) {
        if (this.requests[i].id == this.isSelectedId) {
          if (i + 1 < this.requests.length) {
            this.setSelectedReq(this.requests[i + 1].id);
          } else {
            return false;
          }
          break;
        }
      }
      return true;
    },
    setPrevSelectedElement() {
      for (var i = this.requests.length - 1; i >= 0; i--) {
        if (this.requests[i].id == this.isSelectedId) {
          if (i - 1 >= 0) {
            this.setSelectedReq(this.requests[i - 1].id);
          } else {
            return false;
          }
          break;
        }
      }
      return true;
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
            this.$toast.error(response.message);
          } else {
            this.requests = [];
            if (!response.data) {
              this.$toast.info("No data found");
              return;
            }
            for (var i = 0; i < response.data.length; i++) {
              const newReq = Object.assign({}, response.data[i]);
              newReq.parsed = {};
              newReq.parsed.created_at = dateToString(newReq.created_at);
              newReq.parsed.updated_at = dateToString(newReq.updated_at);
              newReq.parsed.received_at = dateToString(newReq.time_received);
              if (newReq.uri.length > 50) {
                newReq.parsed.uri = newReq.uri.substring(0, 50) + "...";
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
        });
    },
  },
  created() {
    if (this.$route.params.limit) {
      this.limit = parseInt(this.$route.params.limit);
    }

    if (this.$route.params.offset) {
      this.offset = parseInt(this.$route.params.offset);
    }

    if (this.$route.query.q) {
      this.query = this.$route.query.q;
    }

    this.loadRequests(true);
  },
  mounted() {
    const that = this;
    window.addEventListener("keyup", function (event) {
      if (that.searchIsFocused) {
        return;
      }
      if (event.key == "j") {
        if (!that.setPrevSelectedElement()) {
          that.loadPrevRequests();
        }
      } else if (event.key == "k") {
        if (!that.setNextSelectedElement()) {
          that.loadNextRequests();
        }
      }
    });
  },
};
</script>

<style scoped>

.table tr.is-selected {
  background-color: #4e726d;
}

table th {
  color: #616060 !important;
}

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

.restricted-width {
  width: 700px;
}

.p-inputtext {
  width: 100%;
}

.starred {
  color: red;
}
</style>
