<template>
  <div class="list-layout">
    <div class="list-table-wrap">
        <DataTable
          v-model:selection="selectedApp"
          :value="apps"
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
              modelname="application"
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
            field="name"
            header="Name"
            style="width: 20%"
          />
          <DataColumn
            field="vendor"
            header="Vendor"
            style="width: 15%"
          />
          <DataColumn
            field="version"
            header="Version"
            class="col-shrink"
          />
          <DataColumn
            field="os"
            header="OS"
            class="col-shrink"
          />
          <DataColumn
            header="Actions"
            class="col-shrink"
          >
            <template #body="slotProps">
              <a
                :href="config.requestsLink + '?q=app_id:' + slotProps.data.id"
              >
                <i
                  title="Search requests that matched this app"
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
                  @change="onChangeLimit"
                />
              </div>
              <div>
                <i
                  v-if="apps.length == limit"
                  class="pi pi-arrow-right pi-style pi-style-right"
                  @click="loadNext()"
                />
              </div>
            </div>
          </template>
        </DataTable>
    </div>
    <div class="list-form-wrap">
      <app-form
        :app="selectedApp"
        @update-app="onUpdateApps"
        @delete-app="onDeleteApp"
        @require-auth="$emit('require-auth')"
      />
    </div>
  </div>
</template>

<script>
import { dateToString } from "../../helpers.js";
import AppForm from "./AppForm.vue";
import DataSearchBar from "../DataSearchBar.vue";

export default {
  components: {
    AppForm,
    DataSearchBar,
  },
  inject: ["config"],
  emits: ["require-auth"],
  data() {
    return {
      apps: [],
      selectedApp: null,
      isSelectedId: 0,
      query: null,
      limit: 24,
      offset: 0,
      selectedLimit: 21,
      limitOptions: [10, 20, 30, 40, 50],
      isLoading: false,
      baseApp: {
        id: 0,
        name: "",
        version: "",
        vendor: "",
        os: "",
        time_created: "",
        time_updated: "",
      },
    };
  },
  beforeCreate() {
    this.selectedApp = this.baseApp;
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
    } else {
      if (!this.isLoading) {
        this.loadApps(true, function () {});
      }
    }
  },
  methods: {
    onDeleteApp() {
      this.loadApps(true, function () {});
    },
    onUpdateApps(id) {
      console.log("Updated ID " + id);
      const that = this;
      this.loadApps(true, function () {
        that.setSelectedApp(id);
      });
    },
    performNewSearch(query) {
      this.query = query;
      this.offset = 0;
      this.loadApps(true, function () {});
    },
    setSelectedApp(id) {
      var selected = null;
      for (var i = 0; i < this.apps.length; i++) {
        if (this.apps[i].id == id) {
          selected = this.apps[i];
          break;
        }
      }

      if (selected == null) {
        console.log("error: could not find ID: " + id);
      } else {
        this.selectedApp = selected;
        this.isSelectedId = id;
      }
    },
    getAppsLink() {
      let link = this.config.appsLink + "/" + this.offset + "/" + this.limit;
      if (this.query) {
        link += "?q=" + encodeURIComponent(this.query);
      }

      return link;
    },
    loadNext() {
      this.offset += this.limit;
      this.$router.push(this.getAppsLink());
      this.loadApps(true, function () {});
    },
    loadPrev() {
      if (this.offset - this.limit >= 0) {
        this.offset -= this.limit;
        this.$router.push(this.getAppsLink());
        this.loadApps(false, function () {});
      }
    },
    loadApps(selectFirst, callback) {
      this.isLoading = true;
      var url =
        this.config.backendAddress +
        "/app/segment?offset=" +
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
            this.apps = [];
            if (response.data) {
              for (var i = 0; i < response.data.length; i++) {
                const newApp = Object.assign({}, response.data[i]);
                newApp.parsed = {};
                newApp.parsed.created_at = dateToString(newApp.created_at);
                newApp.parsed.updated_at = dateToString(newApp.updated_at);
                this.apps.push(newApp);
              }

              if (selectFirst) {
                this.setSelectedApp(response.data[0].id);
              } else {
                this.setSelectedApp(response.data[response.data.length - 1].id);
              }
            }
          }
          callback();
          this.isLoading = false;
        });
    },
    onChangeLimit() {
      this.limit = this.selectedLimit
      this.loadApps(true, function () {});
    },
  },
};
</script>

<style scoped>
.p-inputtext {
  width: 100%;
}
</style>
