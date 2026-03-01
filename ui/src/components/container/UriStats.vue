<template>
  <div class="stats-page">
    <div class="uristats-header">
      <div class="uristats-header-top">
        <div>
          <div class="uristats-header-label">
            <i class="pi pi-chart-bar" />
            <span>{{ lookupTypeLabel }} Stats</span>
          </div>
          <div class="uristats-header-value" :title="lookupValue">
            {{ truncateValue(lookupValue, 120) }}
          </div>
        </div>
        <div class="uristats-honeypot-filter">
          <label class="uristats-filter-label">
            <i class="pi pi-server" /> Honeypot
          </label>
          <FormSelect
            v-model="selectedHoneypot"
            :options="honeypotOptions"
            option-label="label"
            option-value="value"
            placeholder="All honeypots"
            show-clear
            class="uristats-honeypot-select"
            @change="onHoneypotChange"
          />
        </div>
      </div>
    </div>

    <div
      v-if="isLoading"
      class="uristats-loading"
    >
      <DataSkeleton
        v-for="n in 4"
        :key="n"
        height="3rem"
        class="uristats-skeleton"
      />
    </div>

    <div
      v-else-if="stats"
      class="stats-grid"
    >
      <!-- Summary cards -->
      <div class="stats-card uristats-summary-row">
        <div class="uristats-kv-grid">
          <div class="uristats-kv">
            <div class="uristats-kv-label">
              <i class="pi pi-clock" /> First Seen
            </div>
            <div class="uristats-kv-value">
              {{ formatDate(stats.summary.first_seen) }}
            </div>
          </div>
          <div class="uristats-kv">
            <div class="uristats-kv-label">
              <i class="pi pi-history" /> Last Seen
            </div>
            <div class="uristats-kv-value">
              {{ formatDate(stats.summary.last_seen) }}
            </div>
          </div>
          <div class="uristats-kv">
            <div class="uristats-kv-label">
              <i class="pi pi-globe" /> First Requester IP
            </div>
            <div class="uristats-kv-value">
              <a :href="'/requests?q=source_ip:' + stats.summary.first_requester_ip">
                {{ stats.summary.first_requester_ip || '—' }}
              </a>
            </div>
          </div>
          <div class="uristats-kv">
            <div class="uristats-kv-label">
              <i class="pi pi-list" /> Total Requests
            </div>
            <div class="uristats-kv-value">
              {{ stats.summary.total_requests.toLocaleString() }}
            </div>
          </div>
        </div>
      </div>

      <!-- Per-month chart -->
      <div class="stats-card stats-card-wide">
        <div class="stats-card-header">
          <i class="pi pi-calendar" />
          <span>Requests per Month</span>
        </div>
        <div class="stats-chart-wrap">
          <PrimeChart
            v-if="chartData"
            type="bar"
            :data="chartData"
            :options="chartOptions"
            class="stats-chart"
          />
          <div
            v-else
            class="uristats-no-data"
          >
            No monthly data available.
          </div>
        </div>
      </div>
    </div>

    <div
      v-else-if="errorMessage"
      class="uristats-error"
    >
      <i class="pi pi-exclamation-triangle" />
      {{ errorMessage }}
    </div>
  </div>
</template>

<script>
export default {
  inject: ["config"],
  emits: ["require-auth"],
  data() {
    return {
      isLoading: false,
      stats: null,
      chartData: null,
      chartOptions: null,
      errorMessage: null,
      honeypots: [],
      selectedHoneypot: null,
    };
  },
  computed: {
    lookupType() {
      return this.$route.query.lookup_type || "uri";
    },
    lookupValue() {
      return this.$route.query.lookup_value || "";
    },
    lookupTypeLabel() {
      const labels = { uri: "URI", cmp_hash: "Cmp Hash", base_hash: "Base Hash" };
      return labels[this.lookupType] || this.lookupType;
    },
    honeypotOptions() {
      return this.honeypots.map((h) => ({ label: h.ip, value: h.ip }));
    },
  },
  mounted() {
    this.chartOptions = this.buildChartOptions();
    this.selectedHoneypot = this.$route.query.honeypot_ip || null;
    this.loadHoneypots();
    if (this.lookupValue) {
      this.loadStats();
    } else {
      this.errorMessage = "No lookup value provided.";
    }
  },
  methods: {
    truncateValue(val, max) {
      if (!val) return "";
      return val.length > max ? val.slice(0, max) + "…" : val;
    },
    formatDate(ts) {
      if (!ts) return "—";
      const d = new Date(ts);
      if (isNaN(d.getTime())) return ts;
      return d.toLocaleString();
    },
    loadHoneypots() {
      fetch(this.config.backendAddress + "/honeypot/segment?offset=0&limit=200", {
        headers: { "API-Key": this.$store.getters.apiToken },
      })
        .then((r) => (r.status === 403 ? null : r.json()))
        .then((response) => {
          if (response && response.data) {
            this.honeypots = response.data;
          }
        });
    },
    onHoneypotChange() {
      const query = { ...this.$route.query };
      if (this.selectedHoneypot) {
        query.honeypot_ip = this.selectedHoneypot;
      } else {
        delete query.honeypot_ip;
      }
      this.$router.replace({ query });
      this.loadStats();
    },
    loadStats() {
      this.isLoading = true;
      this.errorMessage = null;

      let url =
        this.config.backendAddress +
        "/stats/uri?lookup_type=" +
        encodeURIComponent(this.lookupType) +
        "&lookup_value=" +
        encodeURIComponent(this.lookupValue);

      if (this.selectedHoneypot) {
        url += "&honeypot_ip=" + encodeURIComponent(this.selectedHoneypot);
      }

      fetch(url, {
        headers: { "API-Key": this.$store.getters.apiToken },
      })
        .then((response) => {
          if (response.status === 403) {
            this.$emit("require-auth");
            return null;
          }
          return response.json();
        })
        .then((response) => {
          this.isLoading = false;
          if (!response) return;
          if (response.status === this.config.backendResultNotOk) {
            this.errorMessage = response.message;
          } else {
            this.stats = response.data;
            this.buildChartData();
          }
        })
        .catch((err) => {
          this.isLoading = false;
          this.errorMessage = err.message;
        });
    },
    buildChartData() {
      if (!this.stats || !this.stats.per_month || !this.stats.per_month.length) {
        this.chartData = null;
        return;
      }
      const documentStyle = getComputedStyle(document.documentElement);
      const labels = this.stats.per_month.map((e) => e.month);
      const data = this.stats.per_month.map((e) => e.total_entries);
      this.chartData = {
        labels,
        datasets: [
          {
            label: "Requests",
            data,
            backgroundColor: documentStyle.getPropertyValue("--p-primary-400") || "rgba(245, 158, 11, 0.7)",
            borderColor: documentStyle.getPropertyValue("--p-primary-600") || "#d97706",
            borderWidth: 1,
          },
        ],
      };
    },
    buildChartOptions() {
      const documentStyle = getComputedStyle(document.documentElement);
      const textColor = documentStyle.getPropertyValue("--p-text-color");
      const textColorSecondary = documentStyle.getPropertyValue("--p-text-muted-color");
      const surfaceBorder = documentStyle.getPropertyValue("--p-content-border-color");
      return {
        maintainAspectRatio: false,
        plugins: {
          legend: { labels: { color: textColor } },
          tooltip: {
            callbacks: {
              label: (ctx) => ` ${ctx.parsed.y.toLocaleString()} requests`,
            },
          },
        },
        scales: {
          x: {
            ticks: { color: textColorSecondary },
            grid: { color: surfaceBorder },
          },
          y: {
            suggestedMin: 0,
            ticks: {
              color: textColorSecondary,
              precision: 0,
            },
            grid: { color: surfaceBorder },
          },
        },
      };
    },
  },
};
</script>

<style scoped>
.stats-page {
  max-width: 1400px;
  margin: 0 auto;
  padding: 1rem;
}

.uristats-header {
  margin-bottom: 1.25rem;
}

.uristats-header-top {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 1.5rem;
  flex-wrap: wrap;
}

.uristats-honeypot-filter {
  display: flex;
  flex-direction: column;
  gap: 0.3rem;
  min-width: 220px;
}

.uristats-filter-label {
  font-size: 0.75rem;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.05em;
  color: var(--p-text-muted-color);
  display: flex;
  align-items: center;
  gap: 0.35rem;
}

.uristats-filter-label i {
  color: var(--p-primary-500);
}

.uristats-honeypot-select {
  width: 100%;
}

.uristats-header-label {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  font-size: 1.15rem;
  font-weight: 700;
  color: var(--p-text-color);
  margin-bottom: 0.25rem;
}

.uristats-header-label i {
  color: var(--p-primary-500);
  font-size: 1.2rem;
}

.uristats-header-value {
  font-family: monospace;
  font-size: 0.85rem;
  color: var(--p-text-muted-color);
  word-break: break-all;
}

.uristats-loading {
  display: flex;
  flex-direction: column;
  gap: 0.75rem;
}

.uristats-skeleton {
  width: 100%;
}

.stats-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
  gap: 1rem;
}

.stats-card {
  background: var(--p-surface-0);
  border: 1px solid var(--p-surface-200);
  border-radius: var(--p-border-radius);
  overflow: hidden;
}

.stats-card-wide {
  grid-column: 1 / -1;
}

.stats-card-header {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  padding: 0.75rem 1rem;
  background: var(--p-surface-50);
  border-bottom: 1px solid var(--p-surface-200);
  font-weight: 600;
  font-size: 0.875rem;
  text-transform: uppercase;
  letter-spacing: 0.03em;
  color: var(--p-text-muted-color);
}

.stats-card-header i {
  font-size: 1rem;
  color: var(--p-primary-500);
}

.uristats-summary-row {
  grid-column: 1 / -1;
  padding: 1rem 1.25rem;
}

.uristats-kv-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: 1rem 2rem;
}

.uristats-kv-label {
  font-size: 0.75rem;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.05em;
  color: var(--p-text-muted-color);
  display: flex;
  align-items: center;
  gap: 0.35rem;
  margin-bottom: 0.25rem;
}

.uristats-kv-label i {
  color: var(--p-primary-500);
}

.uristats-kv-value {
  font-size: 1rem;
  color: var(--p-text-color);
  font-weight: 500;
}

.uristats-kv-value a {
  color: var(--p-primary-600);
  text-decoration: none;
}

.uristats-kv-value a:hover {
  text-decoration: underline;
}

.stats-chart-wrap {
  padding: 1rem;
  height: 22rem;
}

.stats-chart {
  height: 100% !important;
}

.uristats-no-data {
  display: flex;
  align-items: center;
  justify-content: center;
  height: 100%;
  color: var(--p-text-muted-color);
  font-size: 0.9rem;
}

.uristats-error {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  color: var(--p-red-500, #ef4444);
  padding: 1rem;
  background: var(--p-surface-0);
  border: 1px solid var(--p-surface-200);
  border-radius: var(--p-border-radius);
}
</style>
