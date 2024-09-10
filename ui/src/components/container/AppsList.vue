<template>
  <div class="columns">
    <div class="column is-three-fifths" style="margin-left: 15px">
      <DataSearchBar ref="searchBar" @search="performNewSearch"
      modelname="application"></DataSearchBar>

      <table class="table is-hoverable" v-if="apps.length > 0">
        <thead>
          <th>ID</th>
          <th>Name</th>
          <th>Version</th>
          <th>Vendor</th>
          <th>OS</th>
        </thead>
        <tbody>
          <tr
            v-for="app in apps"
            @click="setSelectedApp(app.id)"
            :key="app.id"
            :class="isSelectedId == app.id ? 'is-selected' : ''"
          >
            <td>{{ app.id }}</td>
            <td>{{ app.name }}</td>
            <td>{{ app.version }}</td>
            <td>{{ app.vendor }}</td>
            <td>{{ app.os }}</td>
          </tr>
        </tbody>
      </table>

      <i
        v-if="offset > 0"
        @click="loadPrev()"
        class="pi pi-arrow-left pi-style"
      ></i>
      <i
        v-if="apps.length == limit"
        @click="loadNext()"
        class="pi pi-arrow-right pi-style pi-style-right"
      ></i>
    </div>
    <div
      class="column mright"
      @focusin="keyboardDisabled = true"
      @focusout="keyboardDisabled = false"
    >
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
      keyboardDisabled: false,
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
    setNextSelectedElement() {
      for (var i = 0; i < this.apps.length; i++) {
        if (this.apps[i].id == this.isSelectedId) {
          if (i + 1 < this.apps.length) {
            this.setSelectedApp(this.apps[i + 1].id);
          } else {
            return false;
          }
          break;
        }
      }
      return true;
    },
    setPrevSelectedElement() {
      for (var i = this.apps.length - 1; i >= 0; i--) {
        if (this.apps[i].id == this.isSelectedId) {
          if (i - 1 >= 0) {
            this.setSelectedApp(this.apps[i - 1].id);
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
        });
    },
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

  },
  mounted() {
    if (this.$route.query.q) {
      this.$refs.searchBar.setQuery(this.$route.query.q);
    } else {
      this.loadApps(true, function () {});
    }

    const that = this;
    window.addEventListener("keyup", function (event) {
      if (that.keyboardDisabled) {
        return;
      }
      if (event.key == "j") {
        if (!that.setPrevSelectedElement()) {
          that.loadPrev();
        }
      } else if (event.key == "k") {
        if (!that.setNextSelectedElement()) {
          that.loadNext();
        }
      }
    });
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
