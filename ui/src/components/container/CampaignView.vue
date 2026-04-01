<template>
  <div class="campaign-view" v-if="campaign">
    <div class="campaign-header">
      <h2>
        <i class="pi pi-flag" style="margin-right: 0.5rem;" />
        {{ campaign.name || '(unnamed campaign)' }}
        <i v-if="campaign.feedback_status === 'APPROVED'" class="pi pi-check-circle" style="margin-left: 0.5rem; color: var(--p-green-500);" title="Approved" />
        <i v-else-if="campaign.feedback_status === 'REJECTED'" class="pi pi-times-circle" style="margin-left: 0.5rem; color: var(--p-red-500);" title="Rejected" />
        <PrimeTag
          :value="campaign.status"
          :severity="statusSeverity(campaign.status)"
          style="margin-left: 0.75rem; padding: 0.15rem 0.5rem; font-size: 0.8rem;"
        />
        <PrimeTag
          :value="campaign.severity"
          :severity="severitySeverity(campaign.severity)"
          style="margin-left: 0.5rem; padding: 0.15rem 0.5rem; font-size: 0.8rem;"
        />
      </h2>
    </div>

    <div class="campaign-grid">
      <InfoCard mylabel="Overview">
        <template #default>
          <table>
            <tbody>
              <tr><th>ID</th><td>{{ campaign.id }}</td></tr>
              <tr><th>Requests</th><td>{{ campaign.request_count }}</td></tr>
              <tr><th>First Seen</th><td>{{ parsed.first_seen_at }}</td></tr>
              <tr><th>Last Seen</th><td>{{ parsed.last_seen_at }}</td></tr>
              <tr><th>Created</th><td>{{ parsed.created_at }}</td></tr>
              <tr v-if="agg.timeline.active_days">
                <th>Active Days</th>
                <td>{{ agg.timeline.active_days }}</td>
              </tr>
              <tr v-if="campaign.merged_into_id">
                <th>Merged Into</th>
                <td>
                  <a :href="config.campaignViewLink + '?id=' + campaign.merged_into_id">
                    Campaign #{{ campaign.merged_into_id }}
                  </a>
                </td>
              </tr>
              <tr v-if="campaign.feedback_status && campaign.feedback_status !== 'PENDING'">
                <th>Feedback</th>
                <td>
                  <PrimeTag
                    :value="campaign.feedback_status"
                    :severity="campaign.feedback_status === 'APPROVED' ? 'success' : 'danger'"
                    style="padding: 0.15rem 0.5rem; font-size: 0.8rem;"
                  />
                  <span v-if="campaign.feedback_reason && campaign.feedback_reason !== 'NONE'" style="margin-left: 0.5rem; font-size: 0.85rem; color: var(--p-text-muted-color);">
                    ({{ campaign.feedback_reason }})
                  </span>
                </td>
              </tr>
            </tbody>
          </table>
          <a :href="requestsLink" class="view-requests-link">
            <i class="pi pi-external-link" style="margin-right: 0.4rem;" />
            View all requests
          </a>
          <br>
          <a href="#" @click.prevent="showFingerprintModal = true" class="view-requests-link" style="margin-top: 0.5rem;">
            <i class="pi pi-id-card" style="margin-right: 0.4rem;" />
            View campaign fingerprint
          </a>
        </template>
      </InfoCard>

      <InfoCard mylabel="Targeting">
        <template #default>
          <table>
            <tbody>
              <tr>
                <th>Applications</th>
                <td>
                  <template v-if="(campaign.targeted_apps || []).length > 3">
                    <span v-if="!expanded.apps">
                      {{ campaign.targeted_apps.slice(0, 3).join(', ') }}
                      <a href="#" @click.prevent="expanded.apps = true" style="margin-left: 0.5rem; font-size: 0.85em; text-decoration: underline; color: var(--p-primary-color);">show more ({{ campaign.targeted_apps.length - 3 }})</a>
                    </span>
                    <span v-else>
                      {{ campaign.targeted_apps.join(', ') }}
                      <a href="#" @click.prevent="expanded.apps = false" style="margin-left: 0.5rem; font-size: 0.85em; text-decoration: underline; color: var(--p-primary-color);">show less</a>
                    </span>
                  </template>
                  <template v-else>
                    {{ (campaign.targeted_apps || []).join(', ') || '-' }}
                  </template>
                </td>
              </tr>
              <tr>
                <th>CVEs</th>
                <td>
                  <template v-if="(campaign.targeted_cves || []).length > 3">
                    <span v-if="!expanded.cves">
                      {{ campaign.targeted_cves.slice(0, 3).join(', ') }}
                      <a href="#" @click.prevent="expanded.cves = true" style="margin-left: 0.5rem; font-size: 0.85em; text-decoration: underline; color: var(--p-primary-color);">show more ({{ campaign.targeted_cves.length - 3 }})</a>
                    </span>
                    <span v-else>
                      {{ campaign.targeted_cves.join(', ') }}
                      <a href="#" @click.prevent="expanded.cves = false" style="margin-left: 0.5rem; font-size: 0.85em; text-decoration: underline; color: var(--p-primary-color);">show less</a>
                    </span>
                  </template>
                  <template v-else>
                    {{ (campaign.targeted_cves || []).join(', ') || '-' }}
                  </template>
                </td>
              </tr>
              <tr>
                <th>Source Countries</th>
                <td>{{ (campaign.source_countries || []).join(', ') || '-' }}</td>
              </tr>
              <tr>
                <th>Source ASNs</th>
                <td>{{ (campaign.source_asns || []).join(', ') || '-' }}</td>
              </tr>
              <tr v-if="agg.attack_profile.mitre_techniques && agg.attack_profile.mitre_techniques.length">
                <th>MITRE Techniques</th>
                <td>
                  <template v-if="agg.attack_profile.mitre_techniques.length > 3">
                    <span v-if="!expanded.mitre">
                      {{ agg.attack_profile.mitre_techniques.slice(0, 3).join(', ') }}
                      <a href="#" @click.prevent="expanded.mitre = true" style="margin-left: 0.5rem; font-size: 0.85em; text-decoration: underline; color: var(--p-primary-color);">show more ({{ agg.attack_profile.mitre_techniques.length - 3 }})</a>
                    </span>
                    <span v-else>
                      {{ agg.attack_profile.mitre_techniques.join(', ') }}
                      <a href="#" @click.prevent="expanded.mitre = false" style="margin-left: 0.5rem; font-size: 0.85em; text-decoration: underline; color: var(--p-primary-color);">show less</a>
                    </span>
                  </template>
                  <template v-else>
                    {{ agg.attack_profile.mitre_techniques.join(', ') }}
                  </template>
                </td>
              </tr>
              <tr v-if="agg.attack_profile.vulnerability_types && agg.attack_profile.vulnerability_types.length">
                <th>Vulnerability Types</th>
                <td>
                  <template v-if="agg.attack_profile.vulnerability_types.length > 3">
                    <span v-if="!expanded.vulns">
                      {{ agg.attack_profile.vulnerability_types.slice(0, 3).join(', ') }}
                      <a href="#" @click.prevent="expanded.vulns = true" style="margin-left: 0.5rem; font-size: 0.85em; text-decoration: underline; color: var(--p-primary-color);">show more ({{ agg.attack_profile.vulnerability_types.length - 3 }})</a>
                    </span>
                    <span v-else>
                      {{ agg.attack_profile.vulnerability_types.join(', ') }}
                      <a href="#" @click.prevent="expanded.vulns = false" style="margin-left: 0.5rem; font-size: 0.85em; text-decoration: underline; color: var(--p-primary-color);">show less</a>
                    </span>
                  </template>
                  <template v-else>
                    {{ agg.attack_profile.vulnerability_types.join(', ') }}
                  </template>
                </td>
              </tr>
            </tbody>
          </table>
        </template>
      </InfoCard>
    </div>

    <InfoCard
      v-if="campaign.summary"
      mylabel="Summary"
    >
      <template #default>
        <p style="white-space: pre-wrap; line-height: 1.6;">{{ campaign.summary }}</p>
      </template>
    </InfoCard>

    <div class="campaign-grid" style="margin-top: 1rem;">
      <InfoCard mylabel="Top Source IPs">
        <template #default>
          <table v-if="agg.sources.unique_ips && agg.sources.unique_ips.length">
            <tbody>
              <tr v-for="ip in agg.sources.unique_ips.slice(0, 10)" :key="ip">
                <td>
                  <a :href="config.requestsLink + '?q=source_ip:' + ip">{{ ip }}</a>
                </td>
              </tr>
            </tbody>
          </table>
          <p v-else class="empty-stat">No IP data available</p>
        </template>
      </InfoCard>

      <InfoCard mylabel="Top URIs">
        <template #default>
          <table v-if="agg.attack_profile.top_uris && agg.attack_profile.top_uris.length">
            <thead><tr><th>URI</th><th style="text-align:right;">Count</th></tr></thead>
            <tbody>
              <tr v-for="entry in agg.attack_profile.top_uris.slice(0, 10)" :key="entry.uri">
                <td :title="entry.uri" class="uri-cell">{{ truncate(entry.uri, 60) }}</td>
                <td style="text-align:right;">{{ entry.count }}</td>
              </tr>
            </tbody>
          </table>
          <p v-else class="empty-stat">No URI data available</p>
        </template>
      </InfoCard>
    </div>

    <div class="campaign-grid">
      <InfoCard mylabel="OS Fingerprints">
        <template #default>
          <table v-if="agg.os_fingerprints && agg.os_fingerprints.length">
            <thead><tr><th>OS</th><th style="text-align:right;">Count</th></tr></thead>
            <tbody>
              <tr v-for="entry in agg.os_fingerprints" :key="entry.os">
                <td>{{ entry.os }}</td>
                <td style="text-align:right;">{{ entry.count }}</td>
              </tr>
            </tbody>
          </table>
          <p v-else class="empty-stat">No OS fingerprint data</p>
        </template>
      </InfoCard>

      <InfoCard mylabel="HTTP Methods">
        <template #default>
          <table v-if="Object.keys(agg.behavior.http_methods || {}).length">
            <thead><tr><th>Method</th><th style="text-align:right;">Count</th></tr></thead>
            <tbody>
              <tr v-for="(count, method) in agg.behavior.http_methods" :key="method">
                <td>{{ method }}</td>
                <td style="text-align:right;">{{ count }}</td>
              </tr>
            </tbody>
          </table>
          <p v-else class="empty-stat">No method data</p>
        </template>
      </InfoCard>
    </div>

    <InfoCard
      v-if="Object.keys(agg.timeline.activity_histogram || {}).length"
      mylabel="Activity Timeline"
    >
      <template #default>
        <div class="histogram">
          <div
            v-for="(count, day) in sortedHistogram"
            :key="day"
            class="histogram-bar"
            :title="day + ': ' + count + ' requests'"
          >
            <div class="histogram-fill" :style="{ height: histogramHeight(count) + '%' }"></div>
            <span class="histogram-label">{{ day.slice(5) }}</span>
          </div>
        </div>
      </template>
    </InfoCard>

    <InfoCard
      v-if="agg.behavior.has_downloads"
      mylabel="Downloads & Malware"
    >
      <template #default>
        <p style="margin-bottom: 0.75rem;">{{ agg.behavior.download_count }} download(s) detected</p>
        <table v-if="agg.vt_scanner_results && agg.vt_scanner_results.length">
          <thead>
            <tr>
              <th>SHA256</th>
              <th style="text-align:right;">Malicious</th>
              <th style="text-align:right;">Suspicious</th>
              <th style="text-align:right;">Harmless</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="vt in agg.vt_scanner_results" :key="vt.sha256">
              <td class="mono">{{ truncate(vt.sha256, 16) }}</td>
              <td style="text-align:right;" :class="{ 'text-danger': vt.vt_malicious > 0 }">
                {{ vt.vt_malicious }}
              </td>
              <td style="text-align:right;">{{ vt.vt_suspicious }}</td>
              <td style="text-align:right;">{{ vt.vt_harmless }}</td>
            </tr>
          </tbody>
        </table>
      </template>
    </InfoCard>

    <InfoCard
      v-if="agg.tags && agg.tags.length"
      mylabel="Tags"
    >
      <template #default>
        <PrimeTag
          v-for="tag in agg.tags"
          :key="tag"
          :value="tag"
          severity="info"
          style="margin-right: 0.4rem; margin-bottom: 0.4rem;"
        />
      </template>
    </InfoCard>

    <div style="margin-top: 2rem; padding: 1.5rem; border: 1px solid var(--p-content-border-color); border-radius: 6px; background: var(--p-content-background);">
      <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 1rem;">
        <div>
          <h3 style="margin: 0; display: flex; align-items: center;"><i class="pi pi-check-circle" style="margin-right: 0.5rem;" />Review this Campaign</h3>
          <p style="margin: 0.5rem 0 0 0; font-size: 0.9rem; color: var(--p-text-muted-color);">Classify this campaign to help improve our detection models.</p>
        </div>
        <div class="feedback-actions" style="display: flex; gap: 0.5rem;">
          <PrimeButton label="Approve Campaign" icon="pi pi-check" severity="success" @click="submitFeedback('APPROVED')" />
          <PrimeButton label="Reject Campaign" icon="pi pi-times" severity="danger" @click="showRejectForm = !showRejectForm" />
        </div>
      </div>
      
      <div v-if="showRejectForm" class="reject-form" style="margin-top: 1.5rem; padding-top: 1.5rem; border-top: 1px solid var(--p-content-border-color);">
         <h4 style="margin-bottom: 1rem; margin-top: 0;">Rejection Details</h4>
         <div style="margin-bottom: 1rem;">
           <label style="display: block; margin-bottom: 0.5rem; font-weight: bold; font-size: 0.9rem;">Reason</label>
           <FormSelect v-model="feedback.reason" :options="rejectionReasons" optionLabel="label" optionValue="value" style="width: 100%;" />
         </div>
         <div style="margin-bottom: 1rem;">
           <label style="display: block; margin-bottom: 0.5rem; font-weight: bold; font-size: 0.9rem;">Details (optional)</label>
           <TextArea v-model="feedback.details" rows="3" style="width: 100%;" placeholder="Add context (e.g., 'Duplicate of Campaign #123')"></TextArea>
         </div>
         <div style="display: flex; gap: 0.5rem; justify-content: flex-end;">
           <PrimeButton label="Cancel" severity="secondary" @click="showRejectForm = false" />
           <PrimeButton label="Submit Rejection" severity="danger" @click="submitFeedback('REJECTED')" />
         </div>
      </div>
    </div>

    <PrimeDialog v-model:visible="showFingerprintModal" header="Campaign Fingerprint" :style="{ width: '50rem' }" :breakpoints="{ '1199px': '75vw', '575px': '90vw' }" modal>
      <div style="background: var(--p-content-background); padding: 1rem; border-radius: 6px; border: 1px solid var(--p-content-border-color); overflow-x: auto;">
        <pre style="margin: 0; font-family: monospace; font-size: 0.85rem; color: var(--p-text-color);">{{ formattedFingerprint }}</pre>
      </div>
      <template #footer>
        <PrimeButton label="Close" icon="pi pi-times" @click="showFingerprintModal = false" text />
      </template>
    </PrimeDialog>
  </div>
  <div v-else-if="loadError">
    <p>Error loading campaign: {{ loadError }}</p>
  </div>
  <div v-else>
    <p>Loading campaign...</p>
  </div>
</template>

<script>
import { dateToString, truncateString } from "../../helpers.js";

const emptyAgg = {
  timeline: { activity_histogram: {} },
  sources: { unique_ips: [] },
  attack_profile: { top_uris: [], targeted_apps: [], vulnerability_types: [], mitre_techniques: [], cves: [] },
  behavior: { http_methods: {} },
  os_fingerprints: [],
  vt_scanner_results: [],
  tags: [],
};

export default {
  inject: ["config"],
  emits: ["require-auth"],
  data() {
    return {
      campaign: null,
      parsed: {},
      agg: JSON.parse(JSON.stringify(emptyAgg)),
      loadError: null,
      expanded: {
        apps: false,
        cves: false,
        mitre: false,
        vulns: false,
      },
      showRejectForm: false,
      showFingerprintModal: false,
      feedback: {
        reason: 'NONE',
        details: null,
      },
      rejectionReasons: [
        { value: 'NONE', label: 'None' },
        { value: 'MIXED_ATTACK_TYPES', label: 'Mixed Attack Types (e.g., SQLi mixed with scanning)' },
        { value: 'TOO_MANY_DISTINCT_IPS', label: 'Too Many Distinct IPs/ASNs (Localized attack merged with botnet)' },
        { value: 'TIME_SPAN_TOO_BROAD', label: 'Time Span Too Broad (Unrelated events far apart)' },
        { value: 'DUPLICATE_CAMPAIGN', label: 'Duplicate Campaign (Provide ID in details)' },
        { value: 'POLYMORPHIC_URI', label: 'Polymorphic URI / Minor Payload Variation' },
        { value: 'IPS_ARE_MISSING', label: 'IPs that belong to the same campaign are missing' },
        { value: 'WRONG_IPS_INCLUDED', label: 'IPs that clearly are not part of this campaign were added' },
      ],
    };
  },
  computed: {
    formattedFingerprint() {
      if (!this.campaign || !this.campaign.fingerprint) return 'No fingerprint available.';
      try {
        const obj = typeof this.campaign.fingerprint === 'string' ? JSON.parse(this.campaign.fingerprint) : this.campaign.fingerprint;
        return JSON.stringify(obj, null, 2);
      } catch (e) {
        return this.campaign.fingerprint;
      }
    },
    requestsLink() {
      if (!this.campaign) return '#';
      let query = "campaign_id:" + this.campaign.id;
      const status = this.campaign.status;
      if (this.campaign.first_seen_at) {
        const d = new Date(this.campaign.first_seen_at);
        d.setUTCDate(d.getUTCDate() - 1);
        query += " time_received>" + d.toISOString().slice(0, 10);
      }
      if ((status === "CLOSED" || status === "MERGED") && this.campaign.last_seen_at) {
        const d = new Date(this.campaign.last_seen_at);
        d.setUTCDate(d.getUTCDate() + 1);
        query += " time_received<" + d.toISOString().slice(0, 10);
      }
      return this.config.requestsLink + "?q=" + encodeURIComponent(query);
    },
    sortedHistogram() {
      const hist = this.agg.timeline.activity_histogram || {};
      const sorted = {};
      Object.keys(hist).sort().forEach(k => { sorted[k] = hist[k]; });
      return sorted;
    },
  },
  mounted() {
    const id = this.$route.query.id;
    if (id) {
      this.loadCampaign(id);
    } else {
      this.loadError = "No campaign ID provided.";
    }
  },
  methods: {
    truncate(str, maxlen) {
      return truncateString(str, maxlen);
    },
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
    histogramHeight(count) {
      const hist = this.agg.timeline.activity_histogram || {};
      const max = Math.max(...Object.values(hist), 1);
      return Math.round((count / max) * 100);
    },
    loadCampaign(id) {
      fetch(this.config.backendAddress + "/campaign/single?id=" + id, {
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
            this.loadError = response.message;
          } else {
            this.campaign = response.data;
            this.parsed = {
              first_seen_at: dateToString(this.campaign.first_seen_at),
              last_seen_at: dateToString(this.campaign.last_seen_at),
              created_at: dateToString(this.campaign.created_at),
            };
            if (this.campaign.aggregation_state) {
              try {
                const parsed = (typeof this.campaign.aggregation_state === 'string')
                  ? JSON.parse(this.campaign.aggregation_state)
                  : this.campaign.aggregation_state;
                this.agg = { ...JSON.parse(JSON.stringify(emptyAgg)), ...parsed };
              } catch (e) {
                console.warn('Failed to parse aggregation_state:', e);
              }
            }
          }
        });
    },
    submitFeedback(status) {
      if (!this.campaign) return;
      const payload = {
        id: this.campaign.id,
        status: status,
        reason: status === 'REJECTED' ? this.feedback.reason : 'NONE',
        details: status === 'REJECTED' ? this.feedback.details : null
      };

      fetch(this.config.backendAddress + this.config.campaignFeedbackLink, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "API-Key": this.$store.getters.apiToken,
        },
        body: JSON.stringify(payload),
      })
      .then(response => {
        if (response.status == 403) {
           this.$emit("require-auth");
           return null;
        }
        return response.json();
      })
      .then(response => {
        if (!response) return;
        if (response.status === this.config.backendResultOk) {
          this.$toast.success("Feedback submitted successfully");
          this.showRejectForm = false;
          this.campaign.feedback_status = payload.status;
          this.campaign.feedback_reason = payload.reason;
          this.campaign.feedback_details = payload.details;
        } else {
          this.$toast.error("Failed to submit feedback: " + response.message);
        }
      })
      .catch(error => {
        this.$toast.error("Error submitting feedback: " + error);
      });
    },
  },
};
</script>

<style scoped>
.campaign-view {
  padding: 1.5rem;
}
.campaign-header h2 {
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 0.4rem;
  margin-bottom: 1rem;
}
.campaign-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 1rem;
  margin-bottom: 1rem;
}
@media (max-width: 768px) {
  .campaign-grid {
    grid-template-columns: 1fr;
  }
}
.view-requests-link {
  display: inline-flex;
  align-items: center;
  margin-top: 1rem;
  font-weight: 600;
  font-size: 0.9rem;
}
.campaign-view table th {
  padding-right: 1rem;
  white-space: nowrap;
}
.empty-stat {
  color: var(--p-text-muted-color);
  font-style: italic;
}
.uri-cell {
  font-family: monospace;
  font-size: 0.85rem;
  word-break: break-all;
}
.mono {
  font-family: monospace;
  font-size: 0.85rem;
}
.text-danger {
  color: var(--p-red-500);
  font-weight: 700;
}
.histogram {
  display: flex;
  align-items: flex-end;
  gap: 2px;
  height: 120px;
  padding-top: 0.5rem;
}
.histogram-bar {
  flex: 1;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: flex-end;
  height: 100%;
  min-width: 18px;
}
.histogram-fill {
  width: 100%;
  background: var(--p-primary-color);
  border-radius: 2px 2px 0 0;
  min-height: 2px;
}
.histogram-label {
  font-size: 0.65rem;
  color: var(--p-text-muted-color);
  margin-top: 4px;
  writing-mode: vertical-rl;
  text-orientation: mixed;
}
</style>
