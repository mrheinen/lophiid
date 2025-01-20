<template>
  <div class="columns">
    <div class="column is-three-fifths" style="margin-left: 15px">
      <div class="card">
        <DataTable
          :value="yaras"
          tableStyle="min-width: 50rem"
          :metaKeySelection="true"
          dataKey="id"
          showGridlines
          compareSelectionBy="equals"
          v-model:selection="selectedYara"
          selectionMode="single"
        >
          <template #header>
            <DataSearchBar
              ref="searchBar"
              :isloading="isLoading"
              @search="performNewSearch"
              modelname="yara"
            ></DataSearchBar>
          </template>
          <template #empty>No data matched. </template>
          <template #loading>Loading request data. Please wait. </template>

          <DataColumn field="id" header="ID" style="width: 4%"> </DataColumn>
          <DataColumn
            field="parsed.created_at"
            header="Created at"
            style="width: 12%"
          >
          </DataColumn>
          <DataColumn field="identifier" header="Identfier" style="width: 40%">
          </DataColumn>
          <DataColumn field="download_id" header="Malware ID" style="width: 5%">
            <template #body="slotProps">
              <a
                :href="
                  config.downloadsLink + '?q=id:' + slotProps.data.download_id
                "
              >
                {{ slotProps.data.download_id }}</a
              >
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
                <FormSelect
                  v-model="selectedLimit"
                  @change="onChangeLimit"
                  :options="limitOptions"
                  placeholder="Limit"
                  editable
                  checkmark
                  :highlightOnSelect="false"
                  class="w-full md:w-56"
                />
              </div>
              <div>
                <i
                  v-if="yaras.length == limit"
                  @click="loadNext()"
                  class="pi pi-arrow-right pi-style pi-style-right"
                ></i>
              </div>
            </div>
          </template>
        </DataTable>
      </div>
    </div>
    <div class="column mright">
      <YaraForm :yara="selectedYara"></YaraForm>
    </div>
  </div>
</template>

<script>
import { dateToString } from "../../helpers.js";
import YaraForm from "./YaraForm.vue";
import DataSearchBar from "../DataSearchBar.vue";
export default {
  components: {
    YaraForm,
    DataSearchBar,
  },
  emits: ["require-auth"],
  inject: ["config"],
  data() {
    return {
      yaras: [],
      selectedYara: null,
      isSelectedId: 0,
      query: null,
      limit: 24,
      selectedLimit: 21,
      limitOptions: [10, 20, 30, 40, 50],
      offset: 0,
      isLoading: false,
    };
  },
  methods: {
    onChangeLimit() {
      this.limit = this.selectedLimit
      this.loadYaras(true, function () {});
    },
    onUpdateQuery(id) {
      const that = this;
      this.loadYaras(true, function () {
        that.setSelected(id);
      });
    },
    onDeleteQuery() {
      this.loadYaras(true, function () {});
    },
    performNewSearch(query) {
      this.query = query;
      this.offset = 0;
      this.loadYaras(true, function () {});
    },
    setSelected(id) {
      var selected = null;
      for (var i = 0; i < this.yaras.length; i++) {
        if (this.yaras[i].id == id) {
          selected = this.yaras[i];
          break;
        }
      }

      if (selected == null) {
        console.log("error: could not find ID: " + id);
      } else {
        this.selectedYara = selected;
        this.isSelectedId = id;
      }
    },
    loadNext() {
      this.offset += this.limit;
      this.loadYaras(true, function () {});
    },
    loadPrev() {
      if (this.offset - this.limit >= 0) {
        this.offset -= this.limit;
        this.loadYaras(false, function () {});
      }
    },

    loadYaras(selectFirst, callback) {
      this.isLoading = true;
      var url =
        this.config.backendAddress +
        "/yara/segment?offset=" +
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
            this.yaras = [];
            if (response.data && response.data.length > 0) {
              for (var i = 0; i < response.data.length; i++) {
                const newYara = Object.assign({}, response.data[i]);
                newYara.parsed = {};
                newYara.parsed.created_at = dateToString(newYara.created_at);
                this.yaras.push(newYara);
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
    //this.selectedYara = this.baseQuery;
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
      this.loadYaras(true, function () {});
    },
  },
  mounted() {
    if (this.$route.query.q) {
      this.query = this.$route.query.q;
      this.$refs.searchBar.setQuery(this.$route.query.q);
    }
    this.loadYaras(true, function () {});
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
