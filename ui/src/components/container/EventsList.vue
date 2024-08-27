<template>
  <div class="columns">
    <div class="column is-three-fifths" style="margin-left: 15px">
      <DataSearchBar ref="searchBar" @search="performNewSearch" modelname="ipevent"></DataSearchBar>

      <table class="table is-hoverable" v-if="events.length > 0">
        <thead>
          <th>ID</th>
          <th>Type</th>
          <th>IP</th>
          <th>Request ID</th>
          <th>Domain</th>
          <th>Details</th>
          <th>Source</th>
          <th>Source Ref</th>
          <th>Count</th>
          <th>Actions</th>
        </thead>
        <tbody>
          <tr
            v-for="evt in events"
            @click="setSelected(evt.id)"
            :key="evt.id"
            :class="isSelectedId == evt.id ? 'is-selected' : ''"
          >
            <td>{{ evt.id }}</td>
            <td>{{ evt.type }}</td>
            <td><a :href="config.eventLink + '?q=ip:' + evt.ip">{{ evt.ip }}</a></td>
            <td><a :href="config.requestsLink + '?q=id:' + evt.request_id">{{ evt.request_id }}</a></td>
            <td>{{ evt.domain }}</td>
            <td>{{ evt.details }}</td>
            <td>{{ evt.source }}</td>
            <td v-if="evt.source == 'RULE'"><a :href="config.rulesLink + '?q=id:' + evt.source_ref">{{ evt.source_ref }}</a></td>
            <td v-else-if="evt.source == 'VT'"><a :href="config.downloadsLike + '?q=vt_file_analysis_id:' + evt.source_ref">analysis</a></td>
            <td v-else>{{ evt.source_ref }}</td>
            <td>{{ evt.count }}</td>
            <td>
              <a :href="'/requests?q=source_ip:' + evt.ip">
                <i
                  title="View requests from this IP"
                  class="pi pi-search"
                ></i>
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
        v-if="events.length == limit"
        @click="loadNext()"
        class="pi pi-arrow-right pi-style pi-style-right"
      ></i>
    </div>
    <div
      class="column mright"
      @focusin="keyboardDisabled = true"
      @focusout="keyboardDisabled = false"
    >
      <events-form
        @update-query="onUpdateEvent"
        @require-auth="$emit('require-auth')"
        :event="selectedEvent"
      ></events-form>
    </div>
  </div>
</template>

<script>
function dateToString(inDate) {
  const nd = new Date(Date.parse(inDate));
  return nd.toLocaleString();
}
import EventsForm from "./EventsForm.vue";
import DataSearchBar from "../DataSearchBar.vue";
export default {
  components: {
    EventsForm,
    DataSearchBar,
  },
  emits: ["require-auth"],
  inject: ["config"],
  data() {
    return {
      events: [],
      selected: null,
      isSelectedId: 0,
      query: null,
      limit: 24,
      offset: 0,
      keyboardDisabled: false,
      base: {
        id: 0,
      },
    };
  },
  methods: {
    onUpdateEvent(id) {
      const that = this;
      this.loadEvents(true, function () {
        that.setSelected(id);
      });
    },
    performNewSearch(query) {
      this.query = query;
      this.offset = 0;
      this.loadEvents(true, function () {});
    },
    setSelected(id) {
      var selected = null;
      for (var i = 0; i < this.events.length; i++) {
        if (this.events[i].id == id) {
          selected = this.events[i];
          break;
        }
      }

      if (selected == null) {
        console.log("error: could not find ID: " + id);
      } else {
        this.selectedEvent = selected;
        this.isSelectedId = id;
      }
    },
    getFreshEventLink() {
      return this.config.eventLink + "/0/" + this.limit;
    },
    getEventLink() {
      let link =
        this.config.eventLink +
        "/" +
        this.offset +
        "/" +
        this.limit;
      if (this.query) {
        link += "?q=" + this.query;
      }

      return link;
    },
    setNextSelectedElement() {
      for (var i = 0; i < this.events.length; i++) {
        if (this.events[i].id == this.isSelectedId) {
          if (i + 1 < this.events.length) {
            this.setSelected(this.events[i + 1].id);
          } else {
            return false;
          }
          break;
        }
      }
      return true;
    },
    setPrevSelectedElement() {
      for (var i = this.events.length - 1; i >= 0; i--) {
        if (this.events[i].id == this.isSelectedId) {
          if (i - 1 >= 0) {
            this.setSelected(this.events[i - 1].id);
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
      this.$router.push(this.getEventLink());
      this.loadEvents(true, function () {});
    },
    loadPrev() {
      if (this.offset - this.limit >= 0) {
        this.offset -= this.limit;
        this.$router.push(this.getEventLink());
        this.loadEvents(false, function () {});
      }
    },

    loadEvents(selectFirst, callback) {
      var url =
        this.config.backendAddress +
        "/events/segment?offset=" +
        this.offset +
        "&limit=" +
        this.limit;
      if (this.query) {
        url += "&q=" + this.query;
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
            this.events = [];
            if (response.data && response.data.length > 0) {
              for (var i = 0; i < response.data.length; i++) {
                const newEvent = Object.assign({}, response.data[i]);
                newEvent.parsed = {};
                newEvent.parsed.created_at = dateToString(newEvent.created_at);
                this.events.push(newEvent);
              }

              if (selectFirst) {
                this.setSelected(response.data[0].id);
              } else {
                this.setSelected(response.data[response.data.length - 1].id);
              }
            }
          }
          callback();
        });
    },
  },
  beforeCreate() {
    this.selectedEvent = this.baseEvent;
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
    this.loadEvents(true, function () {});
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
