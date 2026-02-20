<template>
  <div class="list-layout">
    <div class="list-table-wrap">
        <DataTable
          v-model:selection="selectedQuery"
          :value="queries"
          table-style="min-width: 50rem"
          :meta-key-selection="true"
          data-key="id"
          show-gridlines
          compare-selection-by="deepEquals"
          selection-mode="single"
        >
          <template #header>
            <DataSearchBar
              ref="searchBar"
              :isloading="isLoading"
              modelname="storedquery"
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
            field="parsed.created_at"
            header="Created at"
            class="col-shrink"
          />
          <DataColumn
            field="parsed.last_ran_at"
            header="Last ran"
            class="col-shrink"
          />
          <DataColumn header="Query">
            <template #body="slotProps">
              <a :href="config.requestsLink + '?q=' + encodeURIComponent(slotProps.data.query)">{{ slotProps.data.query }}</a>
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
                  @change="onChangeLimit"
                />
              </div>
              <div>
                <i
                  v-if="queries.length == limit"
                  class="pi pi-arrow-right pi-style pi-style-right"
                  @click="loadNext()"
                />
              </div>
            </div>
          </template>
        </DataTable>
    </div>
    <div class="list-form-wrap">
      <query-form
        :query="selectedQuery"
        @update-query="onUpdateQuery"
        @delete-query="onDeleteQuery"
        @require-auth="$emit('require-auth')"
      />
    </div>
  </div>
</template>

<script>
import { dateToString } from "../../helpers.js";
import QueryForm from "./QueryForm.vue";
import DataSearchBar from "../DataSearchBar.vue";
export default {
  components: {
    QueryForm,
    DataSearchBar,
  },
  inject: ["config"],
  emits: ["require-auth"],
  data() {
    return {
      queries: [],
      selectedQuery: null,
      query: null,
      limit: 24,
      selectedLimit: 21,
      limitOptions: [10, 20, 30, 40, 50],
      offset: 0,
      isLoading: false,
      base: {
        id: 0,
        query: "",
        record_count: 0,
        parsed: {
          last_ran_at: "",
        },
      },
    };
  },
  beforeCreate() {
    this.selectedQuery = this.baseQuery;
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
      this.loadQueries(true, function () {});
    }
  },
  methods: {
    onChangeLimit() {
      this.limit = this.selectedLimit
      this.loadQueries(true, function () {});
    },
    onUpdateQuery(id) {
      const that = this;
      this.loadQueries(true, function () {
        that.setSelected(id);
      });
    },
    onDeleteQuery() {
      this.loadQueries(true, function () {});
    },
    performNewSearch(query) {
      this.query = query;
      this.offset = 0;
      this.loadQueries(true, function () {});
    },
    setSelected(id) {
      var selected = null;
      for (var i = 0; i < this.queries.length; i++) {
        if (this.queries[i].id == id) {
          selected = this.queries[i];
          break;
        }
      }

      if (selected == null) {
        console.log("error: could not find ID: " + id);
      } else {
        this.selectedQuery = selected;
      }
    },
    loadNext() {
      this.offset += this.limit;
      this.loadQueries(true, function () {});
    },
    loadPrev() {
      if (this.offset - this.limit >= 0) {
        this.offset -= this.limit;
        this.loadQueries(false, function () {});
      }
    },

    loadQueries(selectFirst, callback) {
      this.isLoading = true;
      var url =
        this.config.backendAddress +
        "/storedquery/segment?offset=" +
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
            this.isLoading = false;
            return;
          }
          if (response.status == this.config.backendResultNotOk) {
            this.$toast.error(response.message);
          } else {
            this.queries = [];
            if (response.data && response.data.length > 0) {
              for (var i = 0; i < response.data.length; i++) {
                const newQuery = Object.assign({}, response.data[i]);
                newQuery.parsed = {};
                newQuery.parsed.created_at = dateToString(newQuery.created_at);
                newQuery.parsed.last_ran_at = dateToString(
                  newQuery.last_ran_at
                );
                this.queries.push(newQuery);
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
.p-inputtext {
  width: 100%;
}
</style>
