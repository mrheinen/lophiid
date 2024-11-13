<template>
  <div class="columns">
    <div class="column is-three-fifths" style="margin-left: 15px">


      <div class="card">
        <DataTable
          :value="events"
          tableStyle="min-width: 50rem"
          :metaKeySelection="true"
          dataKey="id"
          showGridlines
          compareSelectionBy="equals"
          v-model:selection="selectedEvent"
          selectionMode="single"
        >
          <template #header>
            <DataSearchBar
              ref="searchBar"
              :isloading="isLoading"
              @search="performNewSearch"
              modelname="ipevent"
            ></DataSearchBar>
          </template>
          <template #empty>No data matched. </template>
          <template #loading>Loading request data. Please wait. </template>

          <DataColumn field="id" header="ID" style="width: 5%">
          </DataColumn>
          <DataColumn field="parsed.first_seen_at" header="First Seen"
          style="width: 16%">
          </DataColumn>
          <DataColumn field="type" header="Type" style="width: 10%">
          </DataColumn>

          <DataColumn header="IP" style="width: 10%">
            <template #body="slotProps">
              <a :href="config.eventLink + '?q=ip:' + slotProps.data.ip">{{ slotProps.data.ip }}</a>
            </template>
          </DataColumn>
          <DataColumn header="Req ID" style="width: 5%">
            <template #body="slotProps">
              <a :href="config.requestsLink + '?q=id:' + slotProps.data.request_id">{{ slotProps.data.request_id }}</a>
            </template>
          </DataColumn>
          <DataColumn field="details" header="Details" >
          </DataColumn>
          <DataColumn field="source" header="Source" style="width: 5%">
          </DataColumn>
          <DataColumn header="Source ref" style="width: 7%">
            <template #body="slotProps">
              <span v-if="slotProps.data.source == 'RULE'">
                <a :href="config.rulesLink + '?q=id:' + slotProps.data.source_ref">{{ slotProps.data.source_ref }}</a>
              </span>
              <span v-else-if="slotProps.data.source == 'VT'">
                <a :href="config.downloadsLink + '?q=vt_file_analysis_id:' + slotProps.data.source_ref">analysis</a>
              </span>
              <span v-else>{{ slotProps.data.source_ref }}</span>
            </template>
          </DataColumn>
          <DataColumn field="count" header="Count" style="width: 4%">
          </DataColumn>
          <DataColumn header="Actions" style="width: 5%">
            <template #body="slotProps">
              <a :href="config.requestsLink + '?q=source_ip:' + slotProps.data.ip">
                <i
                  title="View requests from this IP"
                  class="pi pi-search"
                ></i>
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
              v-if="events.length == limit"
              @click="loadNext()"
              class="pi pi-arrow-right pi-style pi-style-right"
            ></i>
            </div>
            </div>
          </template>
        </DataTable>
      </div>
    </div>


    <div class="column mright" >
      <events-form
        @update-query="onUpdateEvent"
        @require-auth="$emit('require-auth')"
        :event="selectedEvent"
      ></events-form>
    </div>
  </div>
</template>

<script>
import { dateToString } from "../../helpers.js";

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
      isLoading: false,
      selectedEvent: null,
      limit: 24,
      selectedLimit: 21,
      limitOptions: [10, 20, 30, 40, 50],
      offset: 0,
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
    loadNext() {
      this.offset += this.limit;
      this.loadEvents(true, function () {});
    },
    loadPrev() {
      if (this.offset - this.limit >= 0) {
        this.offset -= this.limit;
        this.loadEvents(false, function () {});
      }
    },

    loadEvents(selectFirst, callback) {
      this.isLoading = true;
      var url =
        this.config.backendAddress +
        "/events/segment?offset=" +
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
            this.events = [];
            if (response.data && response.data.length > 0) {
              for (var i = 0; i < response.data.length; i++) {
                const newEvent = Object.assign({}, response.data[i]);
                newEvent.parsed = {};
                newEvent.parsed.created_at = dateToString(newEvent.created_at);
                if (newEvent.first_seen_at) {
                  newEvent.parsed.first_seen_at = dateToString(newEvent.first_seen_at);
                } else {
                  newEvent.parsed.first_seen_at = dateToString(newEvent.created_at);
                }
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
          this.isLoading = false;
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

    this.selectedLimit = this.limit;
  },
  watch: {
    selectedLimit() {
      this.limit = this.selectedLimit;
      this.loadEvents(true, function () {});
    }
  },
  mounted() {
    if (this.$route.query.q) {
      this.$refs.searchBar.setQuery(this.$route.query.q);
      this.query = this.$route.query.q;
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
