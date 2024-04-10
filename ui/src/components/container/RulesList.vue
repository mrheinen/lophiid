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
      <form
        @submit.prevent="performNewSearch()"
      >
        <span class="p-input-icon-left" style="width: 100%">
          <i class="pi pi-search" />
          <InputText v-model="query" placeholder="Search" />
        </span>
      </form>
      <div>
        <table
          class="table is-hoverable" v-if="rules.length > 0">
          <thead>
            <th>App</th>
            <th>App version</th>
            <th>ID</th>
            <th>Method</th>
            <th>URI / Body</th>
            <th>Port</th>
            <th>Content ID</th>
            <th>Actions</th>
          </thead>
          <tbody>
            <tr
              v-for="rule in appRules"
              @click="setSelectedRule(rule.id)"
              :key="rule.id + rule.alert"
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
              <td>{{ rule.parsed.uri_body }}</td>
              <td>{{ rule.port == 0 ? "Any" : rule.port }}</td>
              <td>
                <a :href="'/content?q=id:' + rule.content_id">
                  {{ rule.content_id }}</a
                >
              </td>

              <td>
                <a :href="'/requests?q=rule_id:' + rule.id">
                  <i
                    title="View requests that matched this rule"
                    class="pi pi-search"
                  ></i>
                </a>
                &nbsp;
                <i
                  @click="toggleAlert(rule)"
                  title="Enable alerting"
                  :class="
                    rule.alert
                      ? 'pi pi-bell pointer alert'
                      : 'pi pi-bell pointer'
                  "
                ></i>
              </td>
            </tr>
          </tbody>
        </table>

        <i
          v-if="offset > 0"
          @click="loadPrevRules()"
          class="pi pi-arrow-left pi-style"
        ></i>
        <i
          v-if="rules.length == limit"
          @click="loadNextRules()"
          class="pi pi-arrow-right pi-style pi-style-right"
        ></i>
      </div>
    </div>
    <div
      class="column mright"
    >
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
function dateToString(inDate) {
  const nd = new Date(Date.parse(inDate));
  return nd.toLocaleString();
}

function truncateString(str, maxlen) {
  if (str.length > maxlen) {
    return str.substring(0, maxlen) + "...";
  }
  return str;
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
      appsLoading: false,
      appRules: [],
      selectedRule: null,
      isSelectedId: 0,
      selectedContentId: 0,
      selectedAppId: 0,
      contentFormVisible: false,
      appFormVisible: false,
      baseRule: {
        host: "",
        uri_matching: "exact",
        body_matching: "exact",
        method: "ANY",
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
    performNewSearch() {
      this.offset = 0;
      this.loadRules(true, function () {});
    },
    loadNextRules() {
      this.offset += this.limit;
      this.$router.push(this.getRulesLink());
      this.loadRules(true, function () {});
    },
    loadPrevRules() {
      if (this.offset - this.limit >= 0) {
        this.offset -= this.limit;
        this.$router.push(this.getRulesLink());
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
    setNextSelectedElement() {
      for (var i = 0; i < this.rules.length; i++) {
        if (this.rules[i].id == this.isSelectedId) {
          if (i + 1 < this.rules.length) {
            this.setSelectedRule(this.rules[i + 1].id);
          } else {
            return false;
          }
          break;
        }
      }
      return true;
    },
    setPrevSelectedElement() {
      for (var i = this.rules.length - 1; i >= 0; i--) {
        if (this.rules[i].id == this.isSelectedId) {
          if (i - 1 >= 0) {
            this.setSelectedRule(this.rules[i - 1].id);
          } else {
            return false;
          }
          break;
        }
      }
      return true;
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

      fetch(this.config.backendAddress + "/app/all", {
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
        url += "&q=" + this.query;
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
    if (this.$route.params.limit) {
      this.limit = parseInt(this.$route.params.limit);
    }

    if (this.$route.params.offset) {
      this.offset = parseInt(this.$route.params.offset);
    }

    if (this.$route.query.q) {
      this.query = this.$route.query.q;
    }

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
  },
  mounted() {
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
