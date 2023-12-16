<template>
  <div class="columns">
    <div class="column is-three-fifths">
      <table class="table is-hoverable" v-if="requests.length > 0">
        <thead>
          <th id="date">Date</th>
          <th>Honeypot</th>
          <th>Method</th>
          <th>Uri</th>
          <th>Src Host</th>
          <th>Port</th>
          <th>Content ID</th>
          <th>Rule ID</th>
        </thead>
        <tbody>
          <tr
            v-for="req in requests"
            @click="setSelectedReq(req.id)"
            :key="req.id"
            :class="isSelectedId == req.id ? 'is-selected' : ''"
          >
            <td>{{ req.parsed.received_at }}</td>
            <td>{{ req.honeypot_ip }}</td>
            <td v-if="req.method == 'POST'">
              {{ req.method }} ({{ req.content_length }})
            </td>
            <td v-else>{{ req.method }}</td>
            <td>{{ req.parsed.uri }}</td>
            <td><a :href="getFreshRequestLink() + '?source_ip=' + req.source_ip"> {{ req.source_ip }}</a></td>
            <td>{{ req.port }}</td>
            <td><a :href="'/content/' + req.content_id">{{ req.content_id }}</a></td>
            <td><a :href="'/rules/' + req.rule_id">{{ req.rule_id }}</a></td>
          </tr>
        </tbody>
      </table>

      <i v-if="offset > 0" @click="loadPrevRequests()" class="pi pi-arrow-left pi-style"></i>
      <i v-if="requests.length == limit"
        @click="loadNextRequests()"
        class="pi pi-arrow-right pi-style pi-style-right"
      ></i>
    </div>
    <div class="column restricted-width">
      <request-view :request="selectedRequest"></request-view>
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
  inject: ["config"],
  data() {
    return {
      requests: [],
      selectedSourceIP: null,
      selectedRequest: null,
      isSelectedId: 0,
      limit: 25,
      offset: 0,
    };
  },
  methods: {
    reloadRequests() {
      this.loadRequests();
    },
    getRequestLink() {
      let link = this.config.requestsLink + "/" + this.offset + "/" + this.limit;
      if (this.selectedSourceIP) {
        link += "?ip=" + this.selectedSourceIP;
      }
      return link;
    },
    getFreshRequestLink() {
      return this.config.requestsLink + "/0/" + this.limit;
    },
    loadNextRequests() {
      this.offset += this.limit;
      this.$router.push(this.getRequestLink());
      this.loadRequests();
    },
    loadPrevRequests() {
      if (this.offset - this.limit >= 0) {
        this.offset -= this.limit;
        this.$router.push(this.getRequestLink());
        this.loadRequests();
      }
    },
    setSelectedReq(id) {
      var selected = null;
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
        this.isSelectedId = id;
      }
    },
    loadRequests() {
      var url = this.config.backendAddress + "/request/segment?offset=" + this.offset + "&limit=" + this.limit

      if (this.selectedSourceIP) {
        url += "&source_ip=" + this.selectedSourceIP;
      }
      fetch(url)
        .then((response) => response.json())
        .then((response) => {
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

    if (this.$route.query.source_ip) {
      this.selectedSourceIP = this.$route.query.source_ip;
    }

    this.loadRequests();
  },
};
</script>

<style scoped>
#date {
  width: 200px;
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
</style>
