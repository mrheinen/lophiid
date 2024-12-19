<template>
  <PrimeDialog v-model:visible="contentFormVisible" modal header="Add content">
    <ContentForm
      @update-content="onAddedContent"
      @require-auth="$emit('require-auth')"
    ></ContentForm>
  </PrimeDialog>

  <PrimeDialog v-model:visible="appFormVisible" modal header="Add application">
    <AppForm
      @update-app="onAddedApp"
      @require-auth="$emit('require-auth')"
    ></AppForm>
  </PrimeDialog>

  <div class="columns">
    <div class="column is-three-fifths" style="margin-left: 15px">


      <div class="card">
        <DataTable
          :value="appRules"
          tableStyle="min-width: 50rem"
          :metaKeySelection="true"
          dataKey="id"
          showGridlines
          compareSelectionBy="equals"
          v-model:selection="selectedRule"
          selectionMode="single"
        >
          <template #header>
            <DataSearchBar
              ref="searchBar"
              :isloading="isLoading"
              @search="performNewSearch"
              modelname="contentrule"
            ></DataSearchBar>
          </template>
          <template #empty>No data matched. </template>
          <template #loading>Loading request data. Please wait. </template>

          <DataColumn field="id" header="ID" style="width: 4%">
          </DataColumn>
          <DataColumn header="App name" style="width: 15%">
            <template #body="slotProps">
             <a :href="config.rulesLink + '?q=app_id:' + slotProps.data.app_id">
               {{ slotProps.data.app_name }} </a
                >
            </template>
          </DataColumn>
          <DataColumn field="app_version" header="App version" style="width: 15%">
          </DataColumn>
          <DataColumn field="method" header="Method" style="width: 6%">
          </DataColumn>
          <DataColumn field="parsed.uri_body" header="Uri / Body">
          </DataColumn>

          <DataColumn header="Port" style="width: 8%">
            <template #body="slotProps">
              {{ slotProps.data.port == 0 ? "Any" : slotProps.data.port }}
            </template>
          </DataColumn>
          <DataColumn header="Content ID" style="width: 8%">
            <template #body="slotProps">
                <a :href="config.contentLink + '?q=id:' + slotProps.data.content_id">
                  {{ slotProps.data.content_id }}</a>
            </template>
          </DataColumn>
          <DataColumn header="Actions" style="width: 6%">
            <template #body="slotProps">
                <a :href="config.requestsLink + '?q=rule_uuid:' + slotProps.data.ext_uuid">
                  <i
                    title="View requests that matched this rule"
                    class="pi pi-search"
                  ></i>
                </a>
                &nbsp;
                <i
                  @click="toggleAlert(slotProps.data)"
                  title="Enable alerting"
                  :class="
                    slotProps.data.alert
                      ? 'pi pi-bell pointer alert'
                      : 'pi pi-bell pointer'
                  "
                ></i>
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
              v-if="appRules.length == limit"
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
      <rule-form
        @update-rule="onUpdatedRule"
        @delete-rule="reloadRules()"
        @content-form-open="showContentForm()"
        @app-form-open="showAppForm()"
        @require-auth="$emit('require-auth')"
        :rule="selectedRule"
        :contentid="selectedContentId"
        :appid="selectedAppId"
      ></rule-form>
    </div>
  </div>
</template>

<script>

import { truncateString, dateToString } from "../../helpers.js";

import RuleForm from "./RuleForm.vue";
import ContentForm from "./ContentForm.vue";
import AppForm from "./AppForm.vue";
import DataSearchBar from "../DataSearchBar.vue";
export default {
  components: {
    RuleForm,
    ContentForm,
    AppForm,
    DataSearchBar,
  },
  inject: ["config"],
  emits: ["require-auth"],
  data() {
    return {
      limit: 24,
      offset: 0,
      rules: [],
      ruleAlertClass: "pi pi-bell pointer",
      rulesLoading: false,
      apps: {},
      query: null,
      selectedLimit: 21,
      limitOptions: [10, 20, 30, 40, 50],
      appsLoading: false,
      appRules: [],
      selectedRule: null,
      isSelectedId: 0,
      selectedContentId: 0,
      selectedAppId: 0,
      contentFormVisible: false,
      appFormVisible: false,
      baseRule: {
        uri_matching: "exact",
        body_matching: "none",
        method: "ANY",
        enabled: true,
        alert: false,
      },
    };
  },
  methods: {
    toggleAlert(rule) {
      var alertRule = null;
      for (var i = 0; i < this.rules.length; i++) {
        if (this.rules[i].id == rule.id) {
          alertRule = this.rules[i];
          rule.alert = !rule.alert;
          alertRule.alert = !alertRule.alert;
          break;
        }
      }

      if (alertRule == null) {
        console.log("Could not find rule with ID: " + rule.id);
        return;
      }

      // Copy it so that when we delete the "parsed" section it does not mess up
      // the UI.
      var copyRule = Object.assign({}, alertRule);

      delete copyRule.parsed;

      fetch(this.config.backendAddress + "/contentrule/upsert", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "API-Key": this.$store.getters.apiToken,
        },
        body: JSON.stringify(copyRule),
      })
        .then((response) => {
          if (response.status == 403) {
            this.$emit("require-auth");
          } else {
            return response.json();
          }
        })
        .then((response) => {
          if (response.status == this.config.backendResultNotOk) {
            this.$toast.error(response.message);
          } else {
            this.$toast.success("Updated rule");
          }
        });
    },
    performNewSearch(query) {
      this.query = query;
      this.offset = 0;
      this.loadRules(true, function () {});
    },
    loadNext() {
      this.offset += this.limit;
      this.loadRules(true, function () {});
    },
    loadPrev() {
      if (this.offset - this.limit >= 0) {
        this.offset -= this.limit;
        this.loadRules(false, function () {});
      }
    },
    getRulesLink() {
      let link = this.config.rulesLink + "/" + this.offset + "/" + this.limit;
      if (this.query) {
        link += "?q=" + this.query;
      }
      return link;
    },
    onUpdatedRule(id) {
      const that = this;
      this.loadRules(true, function () {
        that.setSelectedRule(id);
      });
    },
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
      this.loadRules(true, function () {});
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

      fetch(this.config.backendAddress + "/app/segment?q=&offset=0&limit=1000", {
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
    loadRules(selectFirst, callback) {
      var url =
        this.config.backendAddress +
        "/contentrule/segment?offset=" +
        this.offset +
        "&limit=" +
        this.limit;
      if (this.query) {
        url += "&q=" + encodeURIComponent(this.query);
      }
      this.rulesLoading = true;
      this.loadApps();

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
            this.rules = [];
            if (response.data) {
              for (var i = 0; i < response.data.length; i++) {
                const newRule = Object.assign({}, response.data[i]);
                newRule.parsed = {};

                newRule.parsed.updated_at = dateToString(newRule.updated_at);
                newRule.parsed.uri_body = "";
                if (newRule.uri.length > 0 && newRule.body.length > 0) {
                  newRule.parsed.uri_body += "uri:";
                  newRule.parsed.uri_body += truncateString(newRule.uri, 22);
                  newRule.parsed.uri_body += " body:";
                  newRule.parsed.uri_body += truncateString(newRule.body, 22);
                } else {
                  if (newRule.uri.length > 0) {
                    newRule.parsed.uri_body += "uri:";
                    newRule.parsed.uri_body += truncateString(newRule.uri, 40);
                  } else {
                    newRule.parsed.uri_body += "body:";
                    newRule.parsed.uri_body += truncateString(newRule.body, 40);
                  }
                }

                this.rules.push(newRule);
              }

              if (selectFirst) {
                this.setSelectedRule(response.data[0].id);
              } else {
                this.setSelectedRule(
                  response.data[response.data.length - 1].id
                );
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
    selectedLimit() {
      this.limit = this.selectedLimit;
      this.loadRules(true, function () {});
    },
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
    },
  },
  mounted() {
    if (this.$route.params.limit) {
      this.limit = parseInt(this.$route.params.limit);
    }

    if (this.$route.params.offset) {
      this.offset = parseInt(this.$route.params.offset);
    }

    this.selectedLimit = this.limit;

    if (this.$route.query.q) {
      this.$refs.searchBar.setQuery(this.$route.query.q);
      this.query = this.$route.query.q;
      this.loadRules(true, function () {});
    } else {
      // If a uri and method parameter is given, reset the form and use the given
      // values.
      var that = this;
      this.loadRules(true, function () {
        if (
          that.$route.query.uri ||
          that.$route.query.method ||
          that.$route.query.content_id
        ) {
          var newRule = Object.assign({}, that.baseRule);

          if (that.$route.query.uri) {
            newRule.uri = that.$route.query.uri;
          }

          if (that.$route.query.method) {
            newRule.method = that.$route.query.method;
          }

          if (that.$route.query.content_id) {
            newRule.content_id = parseInt(that.$route.query.content_id);
          }

          that.selectedRule = newRule;
          that.isSelectedId = -1;
        }
      });
    }
  },
};
</script>

<style scoped>
.p-inputtext {
  width: 100%;
}
.table tr.is-selected {
  background-color: #4e726d;
}
i.pi-style {
  font-size: 2rem;
  color: #00d1b2;
}

i.pi-style-right {
  float: right;
}

td {
  font-size: 13px;
}

table {
  width: 100%;
}

.alert {
  color: red;
}

.pointer {
  cursor: pointer;
}
</style>
