<template>
  <div class="grid grid-rows-1 grid-cols-5 gap-4">
    <div
      class="col-span-3"
      style="mleft"
    >
      <div class="rounded overflow-hidden shadow-lg">
        <DataTable
          v-model:selection="selectedEvent"
          :value="events"
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
              modelname="ipevent"
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
            field="parsed.first_seen_at"
            header="First Seen"
            style="width: 16%"
          />
          <DataColumn
            field="type"
            header="Type"
            style="width: 10%"
          >
            <template #body="slotProps">
              <span
                class="pointer filter-cell"
                @click="handleFieldClick($event, 'type', slotProps.data.type)"
              >
                {{ slotProps.data.type }}
                <i v-if="altPressed && !shiftPressed" class="pi pi-search-plus filter-icon" />
                <i v-if="altPressed && shiftPressed" class="pi pi-search-minus filter-icon filter-icon-exclude" />
              </span>
            </template>
          </DataColumn>
          <DataColumn
            field="subtype"
            header="SubType"
            style="width: 10%"
          >
            <template #body="slotProps">
              <span
                class="pointer filter-cell"
                @click="handleFieldClick($event, 'subtype', slotProps.data.subtype)"
              >
                {{ slotProps.data.subtype }}
                <i v-if="altPressed && !shiftPressed" class="pi pi-search-plus filter-icon" />
                <i v-if="altPressed && shiftPressed" class="pi pi-search-minus filter-icon filter-icon-exclude" />
              </span>
            </template>
          </DataColumn>

          <DataColumn
            header="IP"
            style="width: 10%"
          >
            <template #body="slotProps">
              <a
                class="filter-cell"
                :href="config.eventLink + '?q=ip:' + slotProps.data.ip"
                @click="handleFieldClick($event, 'ip', slotProps.data.ip)"
              >
                {{ slotProps.data.ip }}
                <i v-if="altPressed && !shiftPressed" class="pi pi-search-plus filter-icon" />
                <i v-if="altPressed && shiftPressed" class="pi pi-search-minus filter-icon filter-icon-exclude" />
              </a>
            </template>
          </DataColumn>
          <DataColumn
            header="Req ID"
            style="width: 5%"
          >
            <template #body="slotProps">
              <a :href="config.requestsLink + '?q=id:' + slotProps.data.request_id">{{ slotProps.data.request_id }}</a>
            </template>
          </DataColumn>
          <DataColumn
            field="details"
            header="Details"
          />
          <DataColumn
            field="source"
            header="Source"
            style="width: 5%"
          >
            <template #body="slotProps">
              <span
                class="pointer filter-cell"
                @click="handleFieldClick($event, 'source', slotProps.data.source)"
              >
                {{ slotProps.data.source }}
                <i v-if="altPressed && !shiftPressed" class="pi pi-search-plus filter-icon" />
                <i v-if="altPressed && shiftPressed" class="pi pi-search-minus filter-icon filter-icon-exclude" />
              </span>
            </template>
          </DataColumn>
          <DataColumn
            header="Source ref"
            style="width: 7%"
          >
            <template #body="slotProps">
              <span v-if="slotProps.data.source_ref_type == config.ipEventSourceRefRuleId">
                <a :href="config.rulesLink + '?q=id:' + slotProps.data.source_ref">{{ slotProps.data.source_ref }}</a>
              </span>
              <span v-else-if="slotProps.data.source_ref_type == config.ipEventSourceRefDownloadId">
                <a :href="config.downloadsLink + '?q=vt_file_analysis_id:' + slotProps.data.source_ref">analysis</a>
              </span>
              <span v-else>{{ slotProps.data.source_ref }}</span>
            </template>
          </DataColumn>
          <DataColumn
            field="count"
            header="Count"
            style="width: 4%"
          />
          <DataColumn
            header="Actions"
            style="width: 5%"
          >
            <template #body="slotProps">
              <a :href="config.requestsLink + '?q=source_ip:' + slotProps.data.ip">
                <i
                  title="View requests from this IP"
                  class="pi pi-search"
                />
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
                  v-if="events.length == limit"
                  class="pi pi-arrow-right pi-style pi-style-right"
                  @click="loadNext()"
                />
              </div>
            </div>
          </template>
        </DataTable>
      </div>
    </div>


    <div class="col-span-2">
      <events-form
        :event="selectedEvent"
        @update-query="onUpdateEvent"
        @require-auth="$emit('require-auth')"
      />
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
  inject: ["config"],
  emits: ["require-auth"],
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
      altPressed: false,
      shiftPressed: false,
      base: {
        id: 0,
      },
    };
  },
  watch: {
    selectedLimit() {
      this.limit = this.selectedLimit;
      this.loadEvents(true, function () {});
    }
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
  mounted() {
    if (this.$route.query.q) {
      this.$refs.searchBar.setQuery(this.$route.query.q);
      this.query = this.$route.query.q;
    }
    this.loadEvents(true, function () {});
    window.addEventListener('keydown', this.handleKeyDown);
    window.addEventListener('keyup', this.handleKeyUp);
    window.addEventListener('blur', this.handleBlur);
  },
  beforeUnmount() {
    window.removeEventListener('keydown', this.handleKeyDown);
    window.removeEventListener('keyup', this.handleKeyUp);
    window.removeEventListener('blur', this.handleBlur);
  },
  methods: {
    handleBlur() {
      this.altPressed = false;
      this.shiftPressed = false;
    },
    handleKeyDown(event) {
      if (event.key === 'Alt') {
        this.altPressed = true;
      }
      if (event.key === 'Shift') {
        this.shiftPressed = true;
      }
    },
    handleKeyUp(event) {
      if (event.key === 'Alt') {
        this.altPressed = false;
      }
      if (event.key === 'Shift') {
        this.shiftPressed = false;
      }
    },
    handleFieldClick(event, fieldName, value) {
      if (event.altKey) {
        event.preventDefault();
        const prefix = event.shiftKey ? "-" + fieldName + ":" : fieldName + ":";
        const filter = prefix + value;
        const currentQuery = this.query ? this.query.trim() : "";
        const newQuery = currentQuery ? currentQuery + " " + filter : filter;
        this.$refs.searchBar.setQuery(newQuery);
        this.performNewSearch(newQuery);
      }
    },
    onChangeLimit() {
      this.limit = this.selectedLimit
      this.loadEvents(true, function () {});
    },
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

.pointer {
  cursor: pointer;
}

.filter-icon {
  position: absolute;
  right: -10px;
  top: -3px;
  font-size: 0.7rem;
  color: #00d1b2;
}

.filter-icon-exclude {
  color: #e57373;
}

.filter-cell {
  position: relative;
  display: block;
}
</style>
