<template>
  <PrimeDialog
    v-model:visible="contentFormVisible"
    modal
    header="Edit Draft Content (esc disabled)"
    :closeOnEscape="false"
  >
    <ContentForm
      :content="selectedContent"
      @update-content="onUpdatedContent"
      @require-auth="$emit('require-auth')"
    />
  </PrimeDialog>

  <PrimeDialog
    v-model:visible="appFormVisible"
    modal
    header="Edit Draft Application"
  >
    <AppForm
      :app="selectedApp"
      @update-app="onUpdatedApp"
      @require-auth="$emit('require-auth')"
    />
  </PrimeDialog>

  <PrimeDialog
    v-model:visible="ruleFormVisible"
    modal
    header="Edit Draft Rule"
    :style="{ width: '50rem' }"
  >
    <RuleForm
      :rule="selectedRule"
      :contentid="selectedRule.content_id"
      :appid="selectedRule.app_id"
      @update-rule="onUpdatedRule"
      @require-auth="$emit('require-auth')"
    />
  </PrimeDialog>

  <ConfirmPopup />

  <div class="list-layout pt-4">
    <div class="list-table-wrap">
      <DataTable
        v-model:expandedRows="expandedRows"
        :value="draftRules"
        data-key="id"
        table-style="min-width: 50rem"
        show-gridlines
        @rowExpand="onRowExpand"
        @rowCollapse="onRowCollapse"
      >
        <template #header>
          <div class="flex justify-between items-center">
            <h2 class="m-0 text-xl font-bold">Rule Generation Drafts</h2>
            <PrimeButton
              icon="pi pi-refresh"
              label="Reload"
              outlined
              @click="loadDraftRules"
            />
          </div>
        </template>
        <template #empty>
          No pending drafts found.
        </template>
        <template #loading>
          Loading drafts. Please wait.
        </template>

        <DataColumn expander style="width: 5rem" />
        <DataColumn field="id" header="Rule ID" style="width: 10%" />
        <DataColumn header="Target URI / Body">
          <template #body="slotProps">
            {{ formatPattern(slotProps.data) }}
          </template>
        </DataColumn>
        <DataColumn field="method" header="Method" style="width: 15%" />
        <DataColumn field="request_purpose" header="Purpose" style="width: 15%" />

        <template #expansion="slotProps">
          <div class="p-4" style="background-color: var(--p-surface-50); border-radius: var(--p-border-radius)">
            <div class="grid grid-cols-1 lg:grid-cols-3 gap-4">
              
              <!-- Rule details -->
              <PrimeCard class="p-0 shadow-sm">
                <template #title>
                  <div class="flex justify-between items-center text-base">
                    <span>Draft Rule</span>
                    <PrimeButton icon="pi pi-pencil" class="p-button-text p-button-sm" @click="editRule(slotProps.data)" />
                  </div>
                </template>
                <template #content>
                  <div class="text-sm">
                    <p><strong>URI Match:</strong> {{ slotProps.data.uri_matching }}</p>
                    <p><strong>URI:</strong> {{ slotProps.data.uri }}</p>
                    <template v-if="slotProps.data.body_matching && slotProps.data.body_matching.toLowerCase() !== 'none'">
                      <p><strong>Body Match:</strong> {{ slotProps.data.body_matching }}</p>
                      <p><strong>Body:</strong> {{ slotProps.data.body }}</p>
                    </template>
                    <p><strong>Purpose:</strong> {{ slotProps.data.request_purpose }}</p>
                  </div>
                </template>
              </PrimeCard>

              <!-- Application details -->
              <PrimeCard class="shadow-sm">
                <template #title>
                  <div class="flex justify-between items-center text-base">
                    <span>Draft Application</span>
                    <PrimeButton icon="pi pi-pencil" class="p-button-text p-button-sm" @click="editApp(slotProps.data)" />
                  </div>
                </template>
                <template #content>
                  <div v-if="slotProps.data.appData" class="text-sm">
                    <p><strong>Name:</strong> {{ slotProps.data.appData.name }}</p>
                    <p><strong>Vendor:</strong> {{ slotProps.data.appData.vendor }}</p>
                    <p><strong>Version:</strong> {{ slotProps.data.appData.version }}</p>
                    <p v-if="slotProps.data.appData.cves && slotProps.data.appData.cves.length > 0"><strong>CVEs:</strong> {{ slotProps.data.appData.cves.join(', ') }}</p>
                  </div>
                  <DataSkeleton v-else class="mb-2" width="100%" height="4rem" />
                </template>
              </PrimeCard>

              <!-- Content details -->
              <PrimeCard class="shadow-sm">
                <template #title>
                  <div class="flex justify-between items-center text-base">
                    <span>Draft Content</span>
                    <PrimeButton icon="pi pi-pencil" class="p-button-text p-button-sm" @click="editContent(slotProps.data)" />
                  </div>
                </template>
                <template #content>
                  <div v-if="slotProps.data.contentData" class="text-sm">
                    <p><strong>Status:</strong> {{ slotProps.data.contentData.status_code }}</p>
                    <p><strong>Type:</strong> {{ slotProps.data.contentData.content_type }}</p>
                    <p><strong>Server:</strong> {{ slotProps.data.contentData.server }}</p>
                    <div v-if="slotProps.data.contentData.headers && slotProps.data.contentData.headers.length > 0">
                      <p><strong>Headers:</strong></p>
                      <ul class="mt-0 mb-0 pl-3 text-xs font-mono text-surface-600" style="list-style-type: disc">
                        <li v-for="header in slotProps.data.contentData.headers" :key="header" class="break-all">{{ header }}</li>
                      </ul>
                    </div>
                  </div>
                  <DataSkeleton v-else class="mb-2" width="100%" height="4rem" />
                </template>
              </PrimeCard>
            </div>

            <div class="mt-4 flex justify-end items-center gap-4">
              <div class="flex items-center">
                <CheckBox inputId="enableCheckbox" v-model="enableOnApprove" :binary="true" />
                <label for="enableCheckbox" class="ml-2 mt-0 cursor-pointer">Enable when approved</label>
              </div>
              <PrimeButton label="Discard" icon="pi pi-trash" class="p-button-danger p-button-outlined" @click="confirmDiscard($event, slotProps.data)" />
              <PrimeButton label="Approve" icon="pi pi-check" class="p-button-success" @click="approveDraft(slotProps.data)" />
            </div>
          </div>
        </template>
      </DataTable>
    </div>
    
    <div class="list-form-wrap">
      <div v-if="selectedDetails">
        <InfoCard mylabel="Extended Details">
          <div v-if="selectedDetails.contentData">
            <h3 class="mt-0 mb-2 text-base font-semibold text-color">Content Description</h3>
            <p class="text-sm whitespace-pre-wrap p-3" style="background-color: var(--p-surface-100); border-radius: var(--p-border-radius); word-break: break-word;">{{ selectedDetails.contentData.description || 'No description provided.' }}</p>
          </div>
          
          <div v-if="selectedDetails.appData" class="mt-4">
            <h3 class="mb-2 text-base font-semibold text-color">Application References</h3>
            
            <div v-if="selectedDetails.appData.links && selectedDetails.appData.links.length > 0" class="mb-3">
              <span class="text-sm font-semibold text-surface-500">Links:</span>
              <ul class="mt-1 pl-5 text-sm" style="list-style-type: disc">
                <li v-for="link in selectedDetails.appData.links" :key="link" class="mb-1">
                  <a :href="link" target="_blank" rel="noopener noreferrer" class="break-all">{{ link }}</a>
                </li>
              </ul>
            </div>
            
            <div v-if="selectedDetails.appData.cves && selectedDetails.appData.cves.length > 0">
              <span class="text-sm font-semibold text-surface-500">CVEs:</span>
              <div class="mt-2 flex flex-wrap gap-2">
                <a 
                  v-for="cve in selectedDetails.appData.cves" 
                  :key="cve" 
                  :href="'https://nvd.nist.gov/vuln/detail/' + cve" 
                  target="_blank"
                  rel="noopener noreferrer"
                  class="mytag shadow-sm"
                >
                  <i class="pi pi-external-link text-xs mr-1"></i>{{ cve }}
                </a>
              </div>
            </div>
          </div>
        </InfoCard>
      </div>
    </div>
  </div>
</template>

<script>
import RuleForm from "./RuleForm.vue";
import ContentForm from "./ContentForm.vue";
import AppForm from "./AppForm.vue";
import InfoCard from "../cards/InfoCard.vue";
import { truncateString } from "../../helpers.js";

export default {
  components: {
    RuleForm,
    ContentForm,
    AppForm,
    InfoCard,
  },
  inject: ["config"],
  emits: ["require-auth"],
  data() {
    return {
      draftRules: [],
      expandedRows: {},
      enableOnApprove: false,
      
      selectedRule: {},
      selectedContent: {},
      selectedApp: {},
      selectedDetails: null,

      ruleFormVisible: false,
      contentFormVisible: false,
      appFormVisible: false,
    };
  },
  mounted() {
    this.loadDraftRules();
  },
  methods: {
    formatPattern(rule) {
      if (rule.uri && rule.body) {
        return `uri: ${truncateString(rule.uri, 20)} body: ${truncateString(rule.body, 20)}`;
      }
      if (rule.uri) {
        return `uri: ${truncateString(rule.uri, 50)}`;
      }
      return `body: ${truncateString(rule.body, 50)}`;
    },
    loadDraftRules() {
      const url = `${this.config.backendAddress}/contentrule/segment?q=is_draft:true&offset=0&limit=100`;
      fetch(url, {
        headers: { "API-Key": this.$store.getters.apiToken },
      })
      .then(res => {
        if (res.status === 403) {
          this.$emit("require-auth");
          return null;
        }
        return res.json();
      })
      .then(data => {
        if (data && data.status === this.config.backendResultOk) {
          this.draftRules = data.data || [];
          
          this.draftRules.forEach(rule => {
            if (this.expandedRows[rule.id]) {
              if (rule.content_id) this.fetchContent(rule);
              if (rule.app_id) this.fetchApp(rule);
              
              if (this.selectedDetails && this.selectedDetails.id === rule.id) {
                this.selectedDetails = rule;
              }
            }
          });

          if (this.selectedDetails && !this.draftRules.find(r => r.id === this.selectedDetails.id)) {
            this.selectedDetails = null;
          }
        }
      });
    },
    onRowExpand(event) {
      const rule = event.data;
      this.selectedDetails = rule;
      if (!rule.contentData && rule.content_id) {
        this.fetchContent(rule);
      }
      if (!rule.appData && rule.app_id) {
        this.fetchApp(rule);
      }
    },
    onRowCollapse(event) {
      if (this.selectedDetails && this.selectedDetails.id === event.data.id) {
        this.selectedDetails = null;
      }
    },
    fetchContent(rule) {
      fetch(`${this.config.backendAddress}/content/segment?q=id:${rule.content_id}&offset=0&limit=1`, {
        headers: { "API-Key": this.$store.getters.apiToken },
      })
      .then(r => r.json())
      .then(res => {
        if (res.data && res.data.length > 0) {
          rule.contentData = res.data[0];
          if (rule.contentData.data) {
            rule.contentData.data = atob(rule.contentData.data);
          }
        }
      });
    },
    fetchApp(rule) {
      fetch(`${this.config.backendAddress}/app/segment?q=id:${rule.app_id}&offset=0&limit=1`, {
        headers: { "API-Key": this.$store.getters.apiToken },
      })
      .then(r => r.json())
      .then(res => {
        if (res.data && res.data.length > 0) {
          rule.appData = res.data[0];
        }
      });
    },
    editRule(rule) {
      this.selectedRule = { id: 0 };
      this.ruleFormVisible = true;
      this.$nextTick(() => {
        this.$nextTick(() => {
          this.selectedRule = Object.assign({}, rule);
        });
      });
    },
    editContent(rule) {
      this.selectedContent = { id: 0 };
      this.contentFormVisible = true;
      this.$nextTick(() => {
        this.$nextTick(() => {
          if (rule.contentData) {
            this.selectedContent = Object.assign({}, rule.contentData);
          }
        });
      });
    },
    editApp(rule) {
      this.selectedApp = { id: 0 };
      this.appFormVisible = true;
      this.$nextTick(() => {
        this.$nextTick(() => {
          if (rule.appData) {
            this.selectedApp = Object.assign({}, rule.appData);
          }
        });
      });
    },
    onUpdatedRule() {
      this.ruleFormVisible = false;
      this.loadDraftRules();
    },
    onUpdatedContent() {
      this.contentFormVisible = false;
      this.loadDraftRules(); // reload to get new details if expanded again
    },
    onUpdatedApp() {
      this.appFormVisible = false;
      this.loadDraftRules();
    },
    approveDraft(rule) {
      const payload = {
        rule_id: rule.id,
        enable: this.enableOnApprove,
      };
      fetch(`${this.config.backendAddress}/draft/approve`, {
        method: "POST",
        headers: { 
          "API-Key": this.$store.getters.apiToken,
          "Content-Type": "application/json"
        },
        body: JSON.stringify(payload)
      })
      .then(res => {
        if (res.status === 403) {
          this.$emit("require-auth");
        } else {
          return res.json();
        }
      })
      .then(res => {
        if (!res) return;
        if (res.status === this.config.backendResultOk) {
          this.$toast.success("Draft approved successfully");
          this.loadDraftRules();
        } else {
          this.$toast.error(res.message);
        }
      });
    },
    confirmDiscard(event, rule) {
      this.$confirm.require({
        target: event.currentTarget,
        message: "Are you sure you want to discard this draft? This will delete the rule and draft content.",
        icon: "pi pi-exclamation-triangle",
        accept: () => {
          this.discardDraft(rule);
        }
      });
    },
    discardDraft(rule) {
      const payload = { rule_id: rule.id };
      fetch(`${this.config.backendAddress}/draft/discard`, {
        method: "POST",
        headers: { 
          "API-Key": this.$store.getters.apiToken,
          "Content-Type": "application/json"
        },
        body: JSON.stringify(payload)
      })
      .then(res => {
        if (res.status === 403) {
          this.$emit("require-auth");
        } else {
          return res.json();
        }
      })
      .then(res => {
        if (!res) return;
        if (res.status === this.config.backendResultOk) {
          this.$toast.success("Draft discarded");
          this.loadDraftRules();
        } else {
          this.$toast.error(res.message);
        }
      });
    }
  }
};
</script>

<style scoped>
.p-card .p-card-body {
  padding: 1rem;
}
.p-card .p-card-title {
  margin-bottom: 0.5rem;
}
</style>
