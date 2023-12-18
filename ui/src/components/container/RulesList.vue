<template>
  <PrimeDialog v-model:visible="contentFormVisible" modal header="Add content">
    <ContentForm @update-content="onAddedContent"></ContentForm>
  </PrimeDialog>

  <PrimeDialog v-model:visible="appFormVisible" modal header="Add application">
    <AppForm @update-app="onAddedApp"></AppForm>
  </PrimeDialog>

  <div class="columns">
    <div class="column is-three-fifths" style="margin-left: 15px">
      <table class="table is-hoverable" v-if="rules.length > 0">
        <thead>
          <th>App</th>
          <th>App version</th>
          <th>ID</th>
          <th>Method</th>
          <th>Path</th>
          <th>Port</th>
          <th>Content ID</th>
          <th>Date updated</th>
        </thead>
        <tbody>
          <tr
            v-for="rule in appRules"
            @click="setSelectedRule(rule.id)"
            :key="rule.id"
            :class="isSelectedId == rule.id ? 'is-selected' : ''"
          >
            <td
              v-if="rule.rowspan >= 0"
              :rowspan="rule.rowspan > 0 ? rule.rowspan : ''"
            >
              {{ rule.app_name }}
            </td>
            <td
              v-if="rule.rowspan >= 0"
              :rowspan="rule.rowspan > 0 ? rule.rowspan : ''"
            >
              {{ rule.app_version }}
            </td>
            <td>{{ rule.id }}</td>
            <td>{{ rule.method == "ANY" ? "Any" : rule.method }}</td>
            <td>{{ rule.parsed.path }}</td>
            <td>{{ rule.port == 0 ? "Any" : rule.port }}</td>
            <td>
              <a :href="'/content/' + rule.content_id">
                {{ rule.content_id }}</a
              >
            </td>
            <td>{{ rule.parsed.updated_at }}</td>
          </tr>
        </tbody>
      </table>
    </div>
    <div class="column mright">
      <rule-form
        @update-rule="reloadRules()"
        @delete-rule="reloadRules()"
        @content-form-open="showContentForm()"
        @app-form-open="showAppForm()"
        :rule="selectedRule"
        :contentid="selectedContentId"
        :appid="selectedAppId"
      ></rule-form>
    </div>
  </div>
</template>

<script>
function dateToString(inDate) {
  const nd = new Date(Date.parse(inDate));
  return nd.toLocaleString();
}
import RuleForm from "./RuleForm.vue";
import ContentForm from "./ContentForm.vue";
import AppForm from "./AppForm.vue";
export default {
  components: {
    RuleForm,
    ContentForm,
    AppForm,
  },
  inject: ["config"],
  data() {
    return {
      rules: [],
      rulesLoading: false,
      apps: {},
      appsLoading: false,
      appRules: [],
      selectedRule: null,
      isSelectedId: 0,
      selectedContentId: 0,
      selectedAppId: 0,
      contentFormVisible: false,
      appFormVisible: false,
      baseRule: {
        id: 0,
        path: "",
        content_id: 0,
        port: 0,
        path_matching: "",
        method: "",
        time_created: "",
        time_updated: "",
      },
    };
  },
  methods: {
    onAddedContent(id) {
      this.selectedContentId = id;
      this.contentFormVisible = false;
    },
    onAddedApp(id) {
      this.selectedAppId = id;
      this.appFormVisible = false;
    },
    showAppForm() {
      this.appFormVisible = true;
    },
    showContentForm() {
      this.contentFormVisible = true;
    },
    reloadRules() {
      this.loadRules(function () {});
    },
    setSelectedRule(id) {
      var selected = null;
      for (var i = 0; i < this.rules.length; i++) {
        if (this.rules[i].id == id) {
          selected = this.rules[i];
          break;
        }
      }

      if (selected == null) {
        console.log("error: could not find ID: " + id);
      } else {
        this.selectedRule = selected;
        this.isSelectedId = id;
      }
    },
    loadApps() {
      this.appsLoading = true;
      fetch(this.config.backendAddress + "/app/all")
        .then((response) => response.json())
        .then((response) => {
          if (response.status == this.config.backendResultNotOk) {
            this.$toast.error(response.message);
          } else {
            this.apps = {};
            if (response.data) {
              for (var i = 0; i < response.data.length; i++) {
                const newApp = Object.assign({}, response.data[i]);
                if (!newApp.name || newApp.name == "") {
                  newApp.name = "Any";
                  newApp.version = "Any";
                }
                this.apps[newApp.id] = {};
                this.apps[newApp.id].name = newApp.name;
                this.apps[newApp.id].version = newApp.version;
              }
            }
          }
          this.appsLoading = false;
        });
    },
    loadRules(callback) {
      this.rulesLoading = true;
      this.loadApps();
      fetch(this.config.backendAddress + "/contentrule/all")
        .then((response) => response.json())
        .then((response) => {
          if (response.status == this.config.backendResultNotOk) {
            this.$toast.error(response.message);
          } else {
            this.rules = [];
            if (response.data) {
              for (var i = 0; i < response.data.length; i++) {
                const newRule = Object.assign({}, response.data[i]);
                newRule.parsed = {};
                newRule.parsed.created_at = dateToString(newRule.created_at);
                newRule.parsed.updated_at = dateToString(newRule.updated_at);
                if (newRule.path.length > 45) {
                  newRule.parsed.path = newRule.path.substring(0, 45);
                  newRule.parsed.path += "...";
                } else {
                  newRule.parsed.path = newRule.path;
                }

                this.rules.push(newRule);
              }
            }
          }
          callback();
          this.rulesLoading = false;
        });
    },
  },
  beforeCreate() {
    this.selectedRule = this.baseRule;
  },
  computed: {
    isLoading() {
      return this.rulesLoading == true || this.appsLoading == true;
    },
  },
  watch: {
    isLoading(newVal) {
      if (newVal == true) {
        return;
      }

      // In this case apps and/or rules were reloaded.

      this.appRules = [];
      var appCount = {};
      for (var i = 0; i < this.rules.length; i++) {
        var cAppId = this.rules[i].app_id;
        if (appCount[cAppId]) {
          appCount[cAppId]++;
        } else {
          appCount[cAppId] = 1;
        }
        var newRule = Object.assign({}, this.rules[i]);
        if (this.apps[cAppId]) {
          newRule.app_version = this.apps[cAppId].version;
          newRule.app_name = this.apps[cAppId].name;
        } else {
          console.log("App not found in map!");
          console.log(this.apps);
          newRule.app_version = "Any";
          newRule.app_name = "Any";
        }

        this.appRules.push(newRule);
      }

      var appIdToSkip = -1;
      for (var o = 0; o < this.appRules.length; o++) {
        var appId = this.appRules[o].app_id;
        if (appId == appIdToSkip) {
          this.appRules[o].rowspan = -1;
          continue;
        }
        if (appCount[appId] > 1) {
          this.appRules[o].rowspan = appCount[appId];
        } else {
          this.appRules[o].rowspan = 0;
        }
        appIdToSkip = appId;
      }
    },
  },
  created() {
    const maybeSetID = this.$route.params.ruleId;
    const that = this;
    this.loadRules(function () {
      if (maybeSetID) {
        that.setSelectedRule(maybeSetID);
      }
    });
  },
};
</script>
