<template>
  <div class="columns">
    <div class="column is-three-fifths" style="margin-left: 15px">
      <DataSearchBar ref="searchBar" @search="performNewSearch" :options="searchOptions"></DataSearchBar>

      <table class="table is-hoverable" v-if="queries.length > 0">
        <thead>
          <th>ID</th>
          <th>Created at</th>
          <th>Last ran</th>
          <th>Count</th>
          <th>Query</th>
        </thead>
        <tbody>
          <tr
            v-for="query in queries"
            @click="setSelected(query.id)"
            :key="query.id"
            :class="isSelectedId == query.id ? 'is-selected' : ''"
          >
            <td>{{ query.id }}</td>
            <td>{{ query.parsed.created_at }}</td>
            <td>{{ query.parsed.last_ran_at }}</td>
            <td>{{ query.record_count }}</td>
            <td>
              <a :href="'/requests?q=' + encodeURI(query.query)">{{ query.query }}</a>
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
        v-if="queries.length == limit"
        @click="loadNext()"
        class="pi pi-arrow-right pi-style pi-style-right"
      ></i>
    </div>
    <div
      class="column mright"
      @focusin="keyboardDisabled = true"
      @focusout="keyboardDisabled = false"
    >
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
function dateToString(inDate) {
  const nd = new Date(Date.parse(inDate));
  return nd.toLocaleString();
}
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
      selected: null,
      isSelectedId: 0,
      query: null,
      limit: 24,
      offset: 0,
      keyboardDisabled: false,
      base: {
        id: 0,
        query: "",
        record_count: 0,
        parsed: {
          last_ran_at: "",
        },
      },
      searchOptions: new Map([
        ["id", "The ID of the query"],
        ["description", "Description of the query"],
        ["created_at", "Date and time when the query was created"],
        ["updated_at", "Date and time when the query was updated"],
        ["last_ran_at", "Date and time when the query last ran"],
        ["record_count", "Number of matches on query"],
      ]),
    };
  },
  methods: {
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
        this.isSelectedId = id;
      }
    },
    getFreshQueryLink() {
      return this.config.storedquerySegmentLink + "/0/" + this.limit;
    },
    getQueryLink() {
      let link =
        this.config.storedquerySegmentLink +
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
      for (var i = 0; i < this.queries.length; i++) {
        if (this.queries[i].id == this.isSelectedId) {
          if (i + 1 < this.queries.length) {
            this.setSelected(this.queries[i + 1].id);
          } else {
            return false;
          }
          break;
        }
      }
      return true;
    },
    setPrevSelectedElement() {
      for (var i = this.queries.length - 1; i >= 0; i--) {
        if (this.queries[i].id == this.isSelectedId) {
          if (i - 1 >= 0) {
            this.setSelected(this.queries[i - 1].id);
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
      this.$router.push(this.getQueryLink());
      this.loadQueries(true, function () {});
    },
    loadPrev() {
      if (this.offset - this.limit >= 0) {
        this.offset -= this.limit;
        this.$router.push(this.getQueryLink());
        this.loadQueries(false, function () {});
      }
    },

    loadQueries(selectFirst, callback) {
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
        });
    },
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
  },
  mounted() {
    if (this.$route.query.q) {
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
