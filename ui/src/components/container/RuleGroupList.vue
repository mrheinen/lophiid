<template>
  <PrimeDialog
    v-model:visible="appsDialogVisible"
    modal
    header="Manage Applications"
    :style="{ width: '30rem' }"
  >
    <div class="mb-3">
      <label class="label">Applications for group: <b>{{ editingGroupName }}</b></label>
    </div>
    <MultiSelect
      v-model="selectedAppIds"
      :options="allApps"
      option-label="label"
      option-value="value"
      placeholder="Select applications"
      filter
      class="w-full"
    />
    <div class="flex justify-end gap-2 mt-4">
      <PrimeButton
        label="Cancel"
        severity="secondary"
        @click="appsDialogVisible = false"
      />
      <PrimeButton
        label="Save"
        @click="saveAppsForGroup()"
      />
    </div>
  </PrimeDialog>

  <div class="grid grid-rows-1 grid-cols-5 gap-4">
    <div
      class="col-span-3"
      style="mleft"
    >
      <div class="rounded overflow-hidden shadow-lg">
        <DataTable
          v-model:selection="selectedRuleGroup"
          :value="ruleGroups"
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
              modelname="rule_group"
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
            style="width: 4%"
          />
          <DataColumn
            field="name"
            header="Name"
            style="width: 10%"
          />
          <DataColumn
            field="parsed.created_at"
            header="Date"
            style="width: 14%"
          />
          <DataColumn
            header="Actions"
            style="width: 5%"
          >
            <template #body="slotProps">
              <i
                class="pi pi-pencil pi-style-action"
                style="cursor: pointer"
                @click.stop="openAppsDialog(slotProps.data)"
              />
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
                  v-if="ruleGroups.length == limit"
                  class="pi pi-arrow-right pi-style pi-style-right"
                  @click="loadNext()"
                />
              </div>
            </div>
          </template>
        </DataTable>
      </div>
    </div>
    <div class="col-span-2">
      <rule-group-form
        :rulegroup="selectedRuleGroup"
        @update-rule-group="onUpdateRuleGroup"
        @delete-rule-group="onDeleteRuleGroup"
        @require-auth="$emit('require-auth')"
      />
    </div>
  </div>
</template>

<script>
import { dateToString } from "../../helpers.js";
import RuleGroupForm from "./RuleGroupForm.vue";
import DataSearchBar from "../DataSearchBar.vue";
export default {
  components: {
    RuleGroupForm,
    DataSearchBar,
  },
  inject: ["config"],
  emits: ["require-auth"],
  data() {
    return {
      ruleGroups: [],
      selectedRuleGroup: null,
      query: null,
      limit: 24,
      offset: 0,
      selectedLimit: 21,
      limitOptions: [10, 20, 30, 40, 50],
      isLoading: false,
      baseRuleGroup: {
        id: 0,
        name: "",
        parsed: {
          created_at: "",
        },
      },
      appsDialogVisible: false,
      editingGroupId: 0,
      editingGroupName: "",
      allApps: [],
      selectedAppIds: [],
      appsPerGroup: {},
    };
  },
  beforeCreate() {
    this.selectedRuleGroup = this.baseRuleGroup;
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
      this.loadRuleGroups(true, function () {});
    }
  },
  methods: {
    onChangeLimit() {
      this.limit = this.selectedLimit
      this.loadRuleGroups(true, function () {});
    },
    onUpdateRuleGroup(id) {
      const that = this;
      this.loadRuleGroups(true, function () {
        that.setSelected(id);
      });
    },
    onDeleteRuleGroup() {
      this.loadRuleGroups(true, function () {});
    },
    performNewSearch(query) {
      this.query = query;
      this.offset = 0;
      this.loadRuleGroups(true, function () {});
    },
    setSelected(id) {
      var selected = null;
      for (var i = 0; i < this.ruleGroups.length; i++) {
        if (this.ruleGroups[i].id == id) {
          selected = this.ruleGroups[i];
          break;
        }
      }

      if (selected == null) {
        console.log("error: could not find ID: " + id);
      } else {
        this.selectedRuleGroup = selected;
      }
    },
    getFreshRuleGroupLink() {
      return this.config.ruleGroupsLink + "/0/" + this.limit;
    },
    getRuleGroupLink() {
      let link =
        this.config.ruleGroupsLink +
        "/" +
        this.offset +
        "/" +
        this.limit;
      if (this.query) {
        link += "?q=" + encodeURIComponent(this.query);
      }

      return link;
    },
    loadNext() {
      this.offset += this.limit;
      this.loadRuleGroups(true, function () {});
    },
    loadPrev() {
      if (this.offset - this.limit >= 0) {
        this.offset -= this.limit;
        this.loadRuleGroups(false, function () {});
      }
    },

    openAppsDialog(ruleGroup) {
      this.editingGroupId = ruleGroup.id;
      this.editingGroupName = ruleGroup.name;
      this.loadAllApps();
      this.loadAppsPerGroup();
      this.appsDialogVisible = true;
    },
    loadAllApps() {
      fetch(this.config.backendAddress + "/app/segment?offset=0&limit=1000", {
        headers: {
          "API-Key": this.$store.getters.apiToken,
        },
      })
        .then((response) => {
          if (response.status == 403) {
            this.$emit("require-auth");
            return null;
          }
          return response.json();
        })
        .then((response) => {
          if (!response) return;
          if (response.status == this.config.backendResultNotOk) {
            this.$toast.error(response.message);
          } else if (response.data) {
            this.allApps = response.data.map((app) => ({
              label: app.name + " - " + app.version,
              value: app.id,
            }));
          }
        });
    },
    loadAppsPerGroup() {
      fetch(this.config.backendAddress + "/apppergroup/join", {
        headers: {
          "API-Key": this.$store.getters.apiToken,
        },
      })
        .then((response) => {
          if (response.status == 403) {
            this.$emit("require-auth");
            return null;
          }
          return response.json();
        })
        .then((response) => {
          if (!response) return;
          if (response.status == this.config.backendResultNotOk) {
            this.$toast.error(response.message);
          } else if (response.data) {
            this.appsPerGroup = response.data;
            const groupData = this.appsPerGroup[this.editingGroupId];
            if (groupData && groupData.apps) {
              this.selectedAppIds = groupData.apps.map((app) => app.id);
            } else {
              this.selectedAppIds = [];
            }
          }
        });
    },
    saveAppsForGroup() {
      fetch(this.config.backendAddress + "/apppergroup/update", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "API-Key": this.$store.getters.apiToken,
        },
        body: JSON.stringify({
          group_id: this.editingGroupId,
          app_ids: this.selectedAppIds,
        }),
      })
        .then((response) => {
          if (response.status == 403) {
            this.$emit("require-auth");
            return null;
          }
          return response.json();
        })
        .then((response) => {
          if (!response) return;
          if (response.status == this.config.backendResultNotOk) {
            this.$toast.error(response.message);
          } else {
            this.$toast.success("Updated applications for group");
            this.appsDialogVisible = false;
          }
        });
    },
    loadRuleGroups(selectFirst, callback) {
      this.isLoading = true;
      var url =
        this.config.backendAddress +
        "/rulegroup/segment?offset=" +
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
            this.ruleGroups = [];
            if (response.data && response.data.length > 0) {
              for (var i = 0; i < response.data.length; i++) {
                const newRuleGroup = Object.assign({}, response.data[i]);
                newRuleGroup.parsed = {};
                newRuleGroup.parsed.created_at = dateToString(newRuleGroup.created_at);
                this.ruleGroups.push(newRuleGroup);
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

i.pi-style-action {
  font-size: 1.2rem;
  color: #00d1b2;
}

i.pi-style-action:hover {
  color: #00f5d4;
}

.p-inputtext {
  width: 100%;
}
</style>
