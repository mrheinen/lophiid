<template>
  <div class="list-layout">
    <div class="list-table-wrap">
        <DataTable
          v-model:selection="selectedYara"
          :value="yaras"
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
              modelname="yara"
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
            class="col-shrink"
          />
          <DataColumn
            field="parsed.created_at"
            header="Created at"
            class="col-shrink"
          />
          <DataColumn
            field="identifier"
            header="Identfier"
            style="width: 40%"
          />
          <DataColumn
            field="download_id"
            header="Malware ID"
            style="width: 5%"
          >
            <template #body="slotProps">
              <a
                :href="
                  config.downloadsLink + '?q=id:' + slotProps.data.download_id
                "
              >
                {{ slotProps.data.download_id }}</a>
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
                  v-if="yaras.length == limit"
                  class="pi pi-arrow-right pi-style pi-style-right"
                  @click="loadNext()"
                />
              </div>
            </div>
          </template>
        </DataTable>
    </div>
    <div class="list-form-wrap">
      <YaraForm :yara="selectedYara" />
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
  inject: ["config"],
  emits: ["require-auth"],
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
  watch: {
    selectedLimit() {
      this.limit = this.selectedLimit;
      this.loadYaras(true, function () {});
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
  mounted() {
    if (this.$route.query.q) {
      this.query = this.$route.query.q;
      this.$refs.searchBar.setQuery(this.$route.query.q);
    }
    this.loadYaras(true, function () {});
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
};
</script>

<style scoped>
.p-inputtext {
  width: 100%;
}
</style>
