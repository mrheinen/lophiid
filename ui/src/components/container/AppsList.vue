<template>
  <div class="columns">
    <div class="column is-three-fifths" style="margin-left: 15px">


      <div class="card">
        <DataTable
          :value="apps"
          tableStyle="min-width: 50rem"
          :metaKeySelection="true"
          dataKey="id"
          showGridlines
          compareSelectionBy="equals"
          v-model:selection="selectedApp"
          selectionMode="single"
        >
          <template #header>
            <DataSearchBar
              ref="searchBar"
              :isloading="isLoading"
              @search="performNewSearch"
              modelname="application"
            ></DataSearchBar>
          </template>
          <template #empty>No data matched. </template>
          <template #loading>Loading request data. Please wait. </template>

          <DataColumn field="id" header="ID" style="width: 4%">
          </DataColumn>
          <DataColumn field="name" header="Name" style="width: 20%">
          </DataColumn>
          <DataColumn field="vendor" header="Vendor" style="width: 15%">
          </DataColumn>
          <DataColumn field="version" header="Version" style="width: 15%">
          </DataColumn>
          <DataColumn field="os" header="OS" style="width: 15%">
          </DataColumn>
          <DataColumn header="Actions" style="width: 5%">
            <template #body="slotProps">
              <a
                :href="config.requestsLink + '?q=app_id:' + slotProps.data.id"
              >
                <i
                  title="Search requests that matched this app"
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
              v-if="apps.length == limit"
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
      <app-form
        @update-app="onUpdateApps"
        @delete-app="onDeleteApp"
        @require-auth="$emit('require-auth')"
        :app="selectedApp"
      ></app-form>
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
    getFreshAppsLink() {
      return this.config.appsLink + "/0/" + this.limit;
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
  },
  beforeCreate() {
    this.selectedApp = this.baseApp;
  },
  watch: {
    selectedLimit() {
      this.limit = this.selectedLimit;
      if (!this.isLoading) {
        this.loadApps(true, function () {});
      }
    }
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
};
</script>

<style scoped>

.table tr.is-selected {
  background-color: #4e726d;
}

#date {
  width: 170px;
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
