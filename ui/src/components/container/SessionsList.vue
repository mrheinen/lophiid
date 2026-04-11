<template>
  <div class="list-layout">
    <div class="list-table-wrap">
        <DataTable
          v-model:selection="selectedSession"
          :value="sessions"
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
              modelname="session"
              showage="1"
              defaultage="3"
              @search="performNewSearch"
            />
          </template>
          <template #empty>
            No data matched.
          </template>
          <template #loading>
            Loading session data. Please wait.
          </template>
          <DataColumn
            field="parsed.started_at"
            header="Start Time"
            class="col-shrink"
          />

          <DataColumn
            field="id"
            header="ID"
            class="col-shrink"
          >
            <template #body="slotProps">
              <a :href="'/requests?q=session_id:' + slotProps.data.id" @click.stop>
                {{ slotProps.data.id }}
              </a>
            </template>
          </DataColumn>

          <DataColumn
            field="ip"
            header="IP Address"
            style="width: 15%"
          >
            <template #body="slotProps">
              <span
                class="filter-cell pointer"
                @click="handleFieldClick($event, 'ip', slotProps.data.ip)"
              >
                {{ slotProps.data.ip }}
                <i v-if="altPressed && !shiftPressed" class="pi pi-search-plus filter-icon" />
                <i v-if="altPressed && shiftPressed" class="pi pi-search-minus filter-icon filter-icon-exclude" />
              </span>
            </template>
          </DataColumn>

          <DataColumn
            field="kill_chain_process_status"
            header="KC Status"
            class="col-shrink"
          >
            <template #body="slotProps">
              <PrimeBadge
                v-if="slotProps.data.kill_chain_process_status"
                :value="slotProps.data.kill_chain_process_status"
                :severity="slotProps.data.kill_chain_process_status === 'DONE' ? 'success' : slotProps.data.kill_chain_process_status === 'PARTIAL' ? 'warn' : slotProps.data.kill_chain_process_status === 'FAILED' ? 'danger' : 'secondary'"
              />
            </template>
          </DataColumn>
          <DataColumn
            field="parsed.duration"
            header="Duration(s)"
            class="col-shrink"
          />
          <DataColumn
            field="active"
            header="Active"
            class="col-shrink"
          >
            <template #body="slotProps">
              {{ slotProps.data.active ? 'Yes' : 'No' }}
            </template>
          </DataColumn>
          
          <template #footer>
            <div class="flex justify-between items-center">
              <div>
                <i
                  v-if="offset > 0"
                  class="pi pi-arrow-left pi-style"
                  @click="loadPrevSessions()"
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
                  @change="onChangeLimit"
                />
              </div>
              <div>
                <i
                  v-if="sessions.length == limit"
                  class="pi pi-arrow-right pi-style pi-style-right"
                  @click="loadNextSessions()"
                />
              </div>
            </div>
          </template>
        </DataTable>
    </div>
    <div class="list-form-wrap">
      <session-view
        v-if="selectedSession"
        :session="selectedSession"
        :whois="selectedWhois"
      />
    </div>
  </div>
</template>

<script>
import { getDateMinusMonths, dateToString, sharedMixin } from "./../../helpers.js";

import SessionView from "./SessionView.vue";
import DataSearchBar from "../DataSearchBar.vue";
export default {
  components: {
    SessionView,
    DataSearchBar,
  },
  mixins: [sharedMixin],
  inject: ["config"],
  emits: ["require-auth"],
  data() {
    return {
      searchIsFocused: false,
      sessions: [],
      limit: 21,
      selectedSession: null,
      selectedLimit: 21,
      limitOptions: [10, 20, 30, 40, 50],
      query: "active:no",
      searchAgeMonths: 3,
      isSelectedId: 0,
      isLoading: false,
      offset: 0,
      altPressed: false,
      shiftPressed: false,
    };
  },
  watch: {
    selectedSession() {
      if (this.selectedSession) {
        this.loadWhois(this.selectedSession.ip, this.selectedSession.started_at);
      }
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
    } else {
      this.$refs.searchBar.setQuery(this.query);
    }
    this.loadSessions(true);
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
    onChangeLimit() {
      this.limit = this.selectedLimit;
      this.loadSessions(true);
    },
    performNewSearch(query, searchAgeMonths) {
      this.query = query;
      this.searchAgeMonths = searchAgeMonths;
      this.offset = 0;
      this.loadSessions(true);
    },
    handleFieldClick(event, fieldName, value) {
      if (event.altKey) {
        event.preventDefault();
        const prefix = event.shiftKey ? "-" + fieldName + ":" : fieldName + ":";
        const filter = prefix + value;
        const currentQuery = this.query ? this.query.trim() : "";
        const newQuery = currentQuery ? currentQuery + " " + filter : filter;
        this.$refs.searchBar.setQuery(newQuery);
        this.performNewSearch(newQuery, this.searchAgeMonths);
      }
    },
    loadNextSessions() {
      if (this.sessions.length > 0) {
        this.offset += this.limit;
      }
        this.loadSessions(true);
    },
    loadPrevSessions() {
      if (this.offset - this.limit >= 0) {
        this.offset -= this.limit;
        this.loadSessions(false);
      }
    },
    setSelectedSession(id) {
      var selected = null;
      for (var i = 0; i < this.sessions.length; i++) {
        if (this.sessions[i].id == id) {
          selected = this.sessions[i];
          break;
        }
      }

      if (selected == null) {
        console.log("error: could not find ID: " + id);
      } else {
        this.selectedSession = selected;
        this.isSelectedId = id;
      }
    },
    loadSessions(selectFirst) {
      this.isLoading = true;

      var url =
        this.config.backendAddress +
        "/session/segment?offset=" +
        this.offset +
        "&limit=" +
        this.limit;

      if (this.query) {
        var finalQuery = this.query;
        if (this.searchAgeMonths != 0) {
          var searchLimit = getDateMinusMonths(this.searchAgeMonths);
          if (!this.query.includes('started_at:') &&
            !this.query.includes('started_at>') &&
            !this.query.includes('started_at<')) {
            finalQuery = this.query + " started_at>" + searchLimit;
          }
        }
        url += "&q=" + encodeURIComponent(finalQuery);
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
            this.sessions = [];
            if (!response.data || response.data.length == 0) {
              this.$toast.info("No data found");
              this.isLoading = false;
              return;
            }
            for (var i = 0; i < response.data.length; i++) {
              const newSession = Object.assign({}, response.data[i]);
              newSession.parsed = {};
              newSession.parsed.started_at = dateToString(newSession.started_at);
              newSession.parsed.ended_at = dateToString(newSession.ended_at);
              
              var startD = new Date(Date.parse(newSession.started_at));
              var endD = new Date(Date.parse(newSession.ended_at));
              var duration = (endD - startD) / 1000;
              newSession.parsed.duration = duration >= 0 ? duration.toFixed(1) : "0.0";
              
              this.sessions.push(newSession);
            }
            if (selectFirst) {
              this.setSelectedSession(response.data[0].id);
            } else {
              this.setSelectedSession(response.data[response.data.length - 1].id);
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
