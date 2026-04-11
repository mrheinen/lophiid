<template>
  <div class="h-full flex flex-col gap-4">

    <PrimeDialog
      v-model:visible="killChainModalVisible"
      modal
      :header="selectedKillChain ? 'Kill Chain #' + selectedKillChain.id : ''"
      :style="{ width: '60rem', maxWidth: '95vw' }"
    >
      <div v-if="selectedKillChain">
        <table class="session-table mb-4">
          <tbody>
            <tr>
              <th>Started</th>
              <td>{{ selectedKillChain.started_at ? new Date(selectedKillChain.started_at).toLocaleString() : '—' }}</td>
            </tr>
            <tr>
              <th>Model</th>
              <td>{{ selectedKillChain.source_model }}</td>
            </tr>
          </tbody>
        </table>
        <div v-if="!selectedKillChain.phases || selectedKillChain.phases.length === 0" class="text-sm" style="color: var(--p-text-muted-color)">
          No phases recorded.
        </div>
        <table v-else class="session-table">
          <thead>
            <tr>
              <th style="width: 120px">Phase</th>
              <th>Evidence</th>
              <th style="width: 90px">First Req</th>
              <th style="width: 85px">Duration(s)</th>
              <th style="width: 65px">Reqs</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="p in selectedKillChain.phases" :key="p.id">
              <td><PrimeTag :value="p.phase" :severity="phaseSeverity(p.phase)" /></td>
              <td class="evidence-cell">{{ p.evidence }}</td>
              <td><a :href="'/requests?q=id:' + p.first_request_id">{{ p.first_request_id }}</a></td>
              <td>{{ p.phase_duration_seconds }}</td>
              <td>{{ p.request_count }}</td>
            </tr>
          </tbody>
        </table>
      </div>
    </PrimeDialog>
    
    <div>
      <InfoCard mylabel="Session Details">
        <template #default>
          <table class="session-table">
            <tbody>
              <tr>
                <th>ID</th>
                <td>{{ session.id }}</td>
              </tr>
              <tr>
                <th>IP Address</th>
                <td>{{ session.ip }}</td>
              </tr>
              <tr>
                <th>Status</th>
                <td>
                  <PrimeTag :severity="session.active ? 'success' : 'secondary'" :value="session.active ? 'Active' : 'Inactive'" />
                </td>
              </tr>
              <tr>
                <th>Start Time</th>
                <td>{{ session.parsed.started_at }}</td>
              </tr>
              <tr>
                <th>End Time</th>
                <td>{{ session.parsed.ended_at }}</td>
              </tr>
              <tr>
                <th>Duration</th>
                <td>{{ session.parsed.duration }} seconds</td>
              </tr>
            </tbody>
          </table>
        </template>
      </InfoCard>
    </div>

    <div>
      <InfoCard mylabel="Kill Chain">
        <template #default>
          <div v-if="session.kill_chain_process_status">

            <div v-if="killChainsLoading" class="text-sm text-gray-500">Loading kill chains…</div>

            <div v-else-if="killChains.length === 0" class="text-sm text-gray-500">No kill chains recorded.</div>

            <div v-else class="kc-list">
              <div
                v-for="kc in killChains"
                :key="kc.id"
                class="kc-list-row"
                @click="openKillChainModal(kc)"
              >
                <span class="kc-list-id">#{{ kc.id }}</span>
                <span class="flex flex-wrap gap-1">
                  <PrimeTag
                    v-for="phase in uniquePhasesForChain(kc)"
                    :key="phase"
                    :value="phase"
                    :severity="phaseSeverity(phase)"
                  />
                  <span v-if="!kc.phases || kc.phases.length === 0" class="text-sm" style="color: var(--p-text-muted-color)">Loading…</span>
                </span>
                <i class="pi pi-arrow-right ml-auto" style="color: var(--p-text-muted-color); font-size: 0.75rem" />
              </div>
            </div>
          </div>
          <div v-else>
            No Kill Chain records available.
          </div>
        </template>
      </InfoCard>
    </div>

    <div>
      <InfoCard mylabel="Behavior">
        <template #default>
          <table class="session-table">
            <tbody>
              <tr>
                <th>Is Human</th>
                <td>
                    {{ session.behavior_is_human ? 'Yes' : 'No' }}
                </td>
              </tr>
              <tr>
                <th>Has Bursts</th>
                <td>
                    {{ session.behavior_has_bursts ? 'Yes' : 'No' }}
                </td>
              </tr>
              <tr>
                <th>Behavior CV</th>
                <td>{{ session.behavior_cv ? session.behavior_cv.toFixed(3) : 0 }}</td>
              </tr>
              <tr>
                <th>Final Gaps</th>
                <td>
                    <div v-if="session.behavior_final_gaps && session.behavior_final_gaps.length > 0">
                       <span v-for="(gap, index) in session.behavior_final_gaps" :key="index" class="gap-item">{{ gap.toFixed(2) }}</span>
                    </div>
                    <div v-else class="text-sm text-gray-500">No gaps recorded</div>
                </td>
              </tr>
            </tbody>
          </table>
        </template>
      </InfoCard>
    </div>

    <div v-if="whois">
      <InfoCard mylabel="Context">
        <template #default>
          <PrimeTabs value="0">
            <TabList>
              <PrimeTab value="0">
                  Whois
              </PrimeTab>
              <PrimeTab v-if="whois.geoip_country" value="1">
                  Geo
              </PrimeTab>
            </TabList>
            <TabPanels class="request-details-tabs">
              <TabPanel value="0">
                <table class="session-table mb-4">
                    <tbody>
                      <tr v-if="whois.country">
                          <th>Country</th>
                          <td>{{ whois.country }}</td>
                      </tr>
                    </tbody>
                </table>
                <pre v-if="whois.data" class="whois">{{ whois.data }}</pre>
                <pre v-if="whois.rdap_string" class="whois">{{ whois.rdap_string }}</pre>
              </TabPanel>

              <TabPanel v-if="whois.geoip_country" value="1">
                <table class="session-table">
                  <tbody>
                    <tr v-if="whois.geoip_country">
                      <th>GeoIP Country</th>
                      <td>
                        {{ whois.geoip_country }} <span v-if="whois.geoip_country_code">({{ whois.geoip_country_code }})</span>
                        <span v-if="whois.geoip_is_in_eu"> [EU]</span>
                      </td>
                    </tr>
                    <tr v-if="whois.geoip_continent">
                      <th>GeoIP Continent</th>
                      <td>
                        {{ whois.geoip_continent }}
                      </td>
                    </tr>
                    <tr v-if="whois.geoip_city">
                      <th>GeoIP City</th>
                      <td>
                        {{ whois.geoip_city }}
                      </td>
                    </tr>
                    <tr v-if="whois.geoip_asn">
                      <th>GeoIP ASN</th>
                      <td>
                        {{ whois.geoip_asn }} <span v-if="whois.geoip_asn_org">({{ whois.geoip_asn_org }})</span>
                      </td>
                    </tr>
                    <tr v-if="whois.geoip_latitude">
                      <th>GeoIP Location</th>
                      <td>
                        {{ whois.geoip_latitude }}, {{ whois.geoip_longitude }}
                        <span v-if="whois.geoip_accuracy_radius"> (radius: {{ whois.geoip_accuracy_radius }}km)</span>
                      </td>
                    </tr>
                    <tr v-if="whois.geoip_timezone">
                      <th>GeoIP Timezone</th>
                      <td>
                        {{ whois.geoip_timezone }}
                      </td>
                    </tr>
                  </tbody>
                </table>
              </TabPanel>
            </TabPanels>
          </PrimeTabs>
        </template>
      </InfoCard>
    </div>

  </div>
</template>

<script>
import { dateToString } from "../../helpers.js"

export default {
  props: {
    session: {
      type: Object,
      required: true,
    },
    whois: {
      type: Object,
      required: false,
      default: null,
    },
  },
  inject: ["config"],
  data() {
    return {
      killChains: [],
      killChainsLoading: false,
      killChainModalVisible: false,
      selectedKillChain: null,
    };
  },
  watch: {
    session: {
      immediate: true,
      handler(newSession) {
        if (newSession && newSession.id) {
          this.loadKillChains(newSession.id);
        }
      },
    },
  },
  methods: {
    parseWhoisDate(date) {
      if (!date) return "Unknown";
      return dateToString(date);
    },
    loadKillChains(sessionId) {
      this.killChainsLoading = true;
      this.killChains = [];

      const url =
        this.config.backendAddress +
        "/killchain/segment?offset=0&limit=50&q=session_id:" +
        sessionId;

      fetch(url, {
        headers: { "API-Key": this.$store.getters.apiToken },
      })
        .then((r) => r.json())
        .then((response) => {
          if (response.status !== this.config.backendResultOk || !response.data) {
            this.killChainsLoading = false;
            return;
          }
          const chains = response.data;
          const phasePromises = chains.map((kc) => {
            const phaseUrl =
              this.config.backendAddress +
              "/killchainphase/segment?offset=0&limit=100&q=kill_chain_id:" +
              kc.id;
            return fetch(phaseUrl, {
              headers: { "API-Key": this.$store.getters.apiToken },
            })
              .then((r) => r.json())
              .then((pr) => {
                kc.phases = pr.status === this.config.backendResultOk && pr.data ? pr.data : [];
                return kc;
              })
              .catch(() => {
                kc.phases = [];
                return kc;
              });
          });
          Promise.all(phasePromises).then((populated) => {
            this.killChains = populated;
            this.killChainsLoading = false;
          });
        })
        .catch(() => {
          this.killChainsLoading = false;
        });
    },
    openKillChainModal(kc) {
      this.selectedKillChain = kc;
      this.killChainModalVisible = true;
    },
    uniquePhasesForChain(kc) {
      if (!kc.phases) return [];
      const seen = new Set();
      const result = [];
      for (const p of kc.phases) {
        if (!seen.has(p.phase)) {
          seen.add(p.phase);
          result.push(p.phase);
        }
      }
      return result;
    },
    phaseSeverity(phase) {
      const map = {
        RECON: "info",
        VERIFY: "warn",
        EXPLOITATION: "danger",
        CLEANUP: "secondary",
        UNKNOWN: "secondary",
      };
      return map[phase] || "secondary";
    },
  },
};
</script>

<style scoped>
.request-details-tabs {
  padding: 0;
}
.session-table {
  width: 100%;
  border-collapse: collapse;
}
.session-table th, .session-table td {
  text-align: left;
  padding: 0.5rem 0.25rem;
  border-bottom: 1px solid var(--p-surface-200);
}
.session-table th {
  width: 120px;
  font-weight: 600;
  color: var(--p-text-muted-color);
}
.session-table tr:last-child th,
.session-table tr:last-child td {
  border-bottom: none;
}
.gap-item {
    display: inline-block;
    padding: 0.1rem 0.3rem;
    margin-right: 0.2rem;
    margin-bottom: 0.2rem;
    background-color: var(--p-surface-100);
    border-radius: var(--p-border-radius);
    font-size: 0.85rem;
}
.whois-raw-title {
    font-weight: 600;
    margin-bottom: 0.5rem;
    color: var(--p-text-muted-color);
}
.kc-list {
  display: flex;
  flex-direction: column;
  gap: 0.25rem;
}
.kc-list-row {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  padding: 0.5rem 0.6rem;
  border-radius: var(--p-border-radius);
  cursor: pointer;
  border: 1px solid var(--p-surface-200);
  transition: background-color 0.15s;
}
.kc-list-row:hover {
  background-color: var(--p-surface-100);
}
.kc-list-id {
  font-weight: 600;
  min-width: 2.5rem;
  font-size: 0.85rem;
  color: var(--p-text-muted-color);
}
.evidence-cell {
    white-space: normal;
    word-break: break-word;
    max-width: 320px;
    font-size: 0.85rem;
}
.mb-3 {
    margin-bottom: 0.75rem;
}
</style>
