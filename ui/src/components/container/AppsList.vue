<template>
  <div class="columns">
    <div class="column is-three-fifths">
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
    </div>
    <div class="column">
      <app-form @update-app="reloadApps()" :app="selectedApp"></app-form>
    </div>
  </div>
</template>

<script>
function dateToString(inDate) {
  const nd = new Date(Date.parse(inDate));
  return nd.toLocaleString();
}
import AppForm from "./AppForm.vue";
export default {
  components: {
    AppForm,
  },
  inject: ["config"],
  data() {
    return {
      apps: [],
      selectedApp: null,
      isSelectedId: 0,
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
    reloadApps() {
      this.loadApps();
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
    loadApps() {
      fetch(this.config.backendAddress + "/app/all")
        .then((response) => response.json())
        .then((response) => {
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
            }
          }
        });
    },
  },
  beforeCreate() {
    this.selectedApp = this.baseApp;
  },
  created() {
    this.loadApps();
  },
};
</script>
