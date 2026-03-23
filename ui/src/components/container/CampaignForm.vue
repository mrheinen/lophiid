<template>
  <div>
    <div v-if="localCampaign && localCampaign.id">
      <InfoCard mylabel="Campaign details">
        <template #default>
          <table>
            <tbody>
              <tr>
                <th>ID</th>
                <td>{{ localCampaign.id }}</td>
              </tr>
              <tr>
                <th>Name</th>
                <td>{{ localCampaign.name }}</td>
              </tr>
              <tr>
                <th>Status</th>
                <td>
                  <PrimeTag
                    :value="localCampaign.status"
                    :severity="statusSeverity(localCampaign.status)"
                    style="padding: 0.1rem 0.4rem; font-size: 0.75rem;"
                  />
                </td>
              </tr>
              <tr>
                <th>Severity</th>
                <td>
                  <PrimeTag
                    :value="localCampaign.severity"
                    :severity="severitySeverity(localCampaign.severity)"
                    style="padding: 0.1rem 0.4rem; font-size: 0.75rem;"
                  />
                </td>
              </tr>
              <tr>
                <th>Requests</th>
                <td>{{ localCampaign.request_count }}</td>
              </tr>
              <tr v-if="localCampaign.parsed">
                <th>First Seen</th>
                <td>{{ localCampaign.parsed.first_seen_at }}</td>
              </tr>
              <tr v-if="localCampaign.parsed">
                <th>Last Seen</th>
                <td>{{ localCampaign.parsed.last_seen_at }}</td>
              </tr>
              <tr v-if="localCampaign.source_countries && localCampaign.source_countries.length">
                <th>Countries</th>
                <td>{{ localCampaign.source_countries.join(', ') }}</td>
              </tr>
              <tr v-if="localCampaign.source_asns && localCampaign.source_asns.length">
                <th>ASNs</th>
                <td>{{ localCampaign.source_asns.join(', ') }}</td>
              </tr>
              <tr v-if="localCampaign.merged_into_id">
                <th>Merged Into</th>
                <td>
                  <a :href="config.campaignViewLink + '?id=' + localCampaign.merged_into_id">
                    Campaign #{{ localCampaign.merged_into_id }}
                  </a>
                </td>
              </tr>
            </tbody>
          </table>
        </template>
      </InfoCard>

      <InfoCard
        v-if="localCampaign.summary"
        mylabel="Summary"
      >
        <template #default>
          <p style="white-space: pre-wrap;">{{ localCampaign.summary }}</p>
        </template>
      </InfoCard>

      <div style="margin-top: 1rem;">
        <a :href="config.campaignViewLink + '?id=' + localCampaign.id">
          <PrimeButton
            label="View full campaign"
            icon="pi pi-external-link"
            severity="secondary"
            size="small"
          />
        </a>
        <a
          :href="config.requestsLink + '?q=campaign_id:' + localCampaign.id"
          style="margin-left: 0.5rem;"
        >
          <PrimeButton
            label="View requests"
            icon="pi pi-list"
            severity="secondary"
            size="small"
          />
        </a>
      </div>
    </div>
    <div v-else>
      <p>Select a campaign to view details.</p>
    </div>
  </div>
</template>

<script>
export default {
  inject: ["config"],
  props: {
    campaign: {
      type: Object,
      required: false,
      default: null,
    },
  },
  emits: ["require-auth"],
  data() {
    return {
      localCampaign: null,
    };
  },
  watch: {
    campaign() {
      this.localCampaign = this.campaign ? Object.assign({}, this.campaign) : null;
    },
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
  },
};
</script>

<style scoped>
</style>
