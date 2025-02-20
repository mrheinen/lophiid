<template>
  <div class="grid grid-rows-1 grid-cols-5 gap-4">
    <div class="col-span-3" style="mleft">

      <div class="rounded overflow-hidden shadow-lg">
        <DataTable
          :value="queries"
          tableStyle="min-width: 50rem"
          :metaKeySelection="true"
          dataKey="id"
          showGridlines
          compareSelectionBy="deepEquals"
          v-model:selection="selectedQuery"
          selectionMode="single"
        >
          <template #header>
            <DataSearchBar
              ref="searchBar"
              :isloading="isLoading"
              @search="performNewSearch"
              modelname="storedquery"
            ></DataSearchBar>
          </template>
          <template #empty>No data matched. </template>
          <template #loading>Loading request data. Please wait. </template>

          <DataColumn field="id" header="ID" style="width: 4%">
          </DataColumn>
          <DataColumn field="parsed.created_at" header="Created at" style="width: 12%">
          </DataColumn>
          <DataColumn field="parsed.last_ran_at" header="Last ran" style="width: 12%">
          </DataColumn>
          <DataColumn header="Query">
            <template #body="slotProps">
              <a :href="config.requestsLink + '?q=' + encodeURI(slotProps.data.query)">{{ slotProps.data.query }}</a>
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

            <FormSelect v-model="selectedLimit"  @change="onChangeLimit" :options="limitOptions" placeholder="Limit" editable checkmark :highlightOnSelect="false" class="w-full md:w-56" />
            </div>
            <div>
            <i
              v-if="queries.length == limit"
              @click="loadNext()"
              class="pi pi-arrow-right pi-style pi-style-right"
            ></i>
            </div>
            </div>
          </template>


        </DataTable>
      </div>
    </div>
    <div class="col-span-2">
      <query-form
        @update-query="onUpdateQuery"
        @delete-query="onDeleteQuery"
        @require-auth="$emit('require-auth')"
        :query="selectedQuery"
      ></query-form>
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
  emits: ["require-auth"],
  inject: ["config"],
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
      console.log(id);
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
  beforeCreate() {
    this.selectedQuery = this.baseQuery;
  },
  watch: {
    selectedQuery(test){
      console.log(test);
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
      this.loadQueries(true, function () {});
    }
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
