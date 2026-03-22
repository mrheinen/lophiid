<template>
  <div class="list-layout">
    <div class="list-table-wrap">
        <DataTable
          v-model:selection="selectedCampaign"
          :value="campaigns"
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
              modelname="campaign"
              @search="performNewSearch"
            />
          </template>
          <template #empty>
            No data matched.
          </template>
          <template #loading>
            Loading campaign data. Please wait.
          </template>

          <DataColumn
            field="id"
            header="ID"
            style="width: 4%"
          />
          <DataColumn
            field="name"
            header="Name"
            style="width: 25%"
          >
            <template #body="slotProps">
              <a :href="config.campaignViewLink + '?id=' + slotProps.data.id">
                {{ slotProps.data.name || '(unnamed)' }}
              </a>
            </template>
          </DataColumn>
          <DataColumn
            field="status"
            header="Status"
            style="width: 8%"
          />
          <DataColumn
            field="severity"
            header="Severity"
            style="width: 8%"
          />
          <DataColumn
            field="request_count"
            header="Requests"
            style="width: 7%"
          />
          <DataColumn
            field="parsed.age_days"
            header="Age (days)"
            style="width: 7%"
          />
          <DataColumn
            field="parsed.ip_count"
            header="IPs"
            style="width: 6%"
          />
          <DataColumn
            field="parsed.last_seen_at"
            header="Last Seen"
            class="col-shrink"
          />

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
                  @change="onChangeLimit()"
                />
              </div>
              <div>
                <i
                  v-if="campaigns.length == limit"
                  class="pi pi-arrow-right pi-style pi-style-right"
                  @click="loadNext()"
                />
              </div>
            </div>
          </template>
        </DataTable>
    </div>
    <div class="list-form-wrap">
      <campaign-form
        :campaign="selectedCampaign"
        @require-auth="$emit('require-auth')"
      />
    </div>
  </div>
</template>

<script>
import { dateToString } from "../../helpers.js";
import CampaignForm from "./CampaignForm.vue";
import DataSearchBar from "../DataSearchBar.vue";
export default {
  components: {
    CampaignForm,
    DataSearchBar,
  },
  inject: ["config"],
  emits: ["require-auth"],
  data() {
    return {
      campaigns: [],
      isLoading: false,
      selectedCampaign: null,
      limit: 24,
      selectedLimit: 24,
      limitOptions: [10, 20, 30, 40, 50],
      offset: 0,
      query: "-status:MERGED",
    };
  },
  watch: {
    selectedLimit() {
      this.limit = this.selectedLimit;
      this.loadCampaigns(true, function () {});
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
      this.query = this.$route.query.q;
    } else {
      this.$refs.searchBar.setQuery(this.query);
    }
    this.loadCampaigns(true, function () {});
  },
  methods: {
    statusSeverity(status) {
      switch (status) {
        case 'ACTIVE': return 'danger';
        case 'DORMANT': return 'warn';
        case 'CLOSED': return 'secondary';
        case 'MERGED': return 'info';
        default: return 'secondary';
      }
    },
    severitySeverity(severity) {
      switch (severity) {
        case 'CRITICAL': return 'danger';
        case 'HIGH': return 'warn';
        case 'MEDIUM': return 'info';
        case 'LOW': return 'secondary';
        default: return 'secondary';
      }
    },
    onChangeLimit() {
      this.limit = this.selectedLimit;
      this.loadCampaigns(true, function () {});
    },
    performNewSearch(query) {
      this.query = query;
      this.offset = 0;
      this.loadCampaigns(true, function () {});
    },
    setSelected(id) {
      var selected = null;
      for (var i = 0; i < this.campaigns.length; i++) {
        if (this.campaigns[i].id == id) {
          selected = this.campaigns[i];
          break;
        }
      }
      if (selected != null) {
        this.selectedCampaign = selected;
      }
    },
    loadNext() {
      this.offset += this.limit;
      this.loadCampaigns(true, function () {});
    },
    loadPrev() {
      if (this.offset - this.limit >= 0) {
        this.offset -= this.limit;
        this.loadCampaigns(false, function () {});
      }
    },
    loadCampaigns(selectFirst, callback) {
      this.isLoading = true;
      var url =
        this.config.backendAddress +
        "/campaign/segment?offset=" +
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
            this.campaigns = [];
            if (response.data && response.data.length > 0) {
              for (var i = 0; i < response.data.length; i++) {
                const c = Object.assign({}, response.data[i]);
                c.parsed = {};
                c.parsed.last_seen_at = dateToString(c.last_seen_at);
                c.parsed.first_seen_at = dateToString(c.first_seen_at);
                const first = new Date(c.first_seen_at);
                const last = new Date(c.last_seen_at);
                c.parsed.age_days = Math.max(0, Math.round((last - first) / (1000 * 60 * 60 * 24)));
                try {
                  const agg = JSON.parse(c.aggregation_state || '{}');
                  c.parsed.ip_count = (agg.sources && agg.sources.unique_ips) ? agg.sources.unique_ips.length : 0;
                } catch (e) {
                  c.parsed.ip_count = 0;
                }
                this.campaigns.push(c);
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
