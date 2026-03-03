<template>
  <div class="stats-page">
    <div class="stats-grid">
      <!-- Line Charts -->
      <div class="stats-card stats-card-wide">
        <div class="stats-card-header">
          <i class="pi pi-calendar" />
          <span>Requests per Month</span>
        </div>
        <div class="stats-chart-wrap">
          <PrimeChart
            type="line"
            :data="rpmChartData"
            :options="chartOptions2"
            class="stats-chart"
          />
        </div>
      </div>

      <div class="stats-card stats-card-wide">
        <div class="stats-card-header">
          <i class="pi pi-chart-line" />
          <span>Requests per Day</span>
        </div>
        <div class="stats-chart-wrap">
          <PrimeChart
            type="line"
            :data="rpdChartData"
            :options="chartOptions"
            class="stats-chart"
          />
        </div>
      </div>

      <div class="stats-card stats-card-wide">
        <div class="stats-card-header">
          <i class="pi pi-download" />
          <span>Downloads per Day</span>
        </div>
        <div class="stats-chart-wrap">
          <PrimeChart
            type="line"
            :data="dpdChartData"
            :options="chartOptions2"
            class="stats-chart"
          />
        </div>
      </div>

      <!-- Doughnut Charts -->
      <div class="stats-card">
        <div class="stats-card-header">
          <i class="pi pi-chart-pie" />
          <span>Methods (24h)</span>
        </div>
        <div class="stats-pie-wrap">
          <PrimeChart
            type="doughnut"
            :data="methodPieChartData"
            :options="pieChartOptions"
          />
        </div>
      </div>

      <!-- Top Source IPs -->
      <div
        v-if="stats"
        class="stats-card"
      >
        <div class="stats-card-header">
          <i class="pi pi-globe" />
          <span>Top Source IPs (24h)</span>
        </div>
        <div class="stats-table-wrap">
          <table>
            <thead>
              <tr>
                <th>Source IP</th>
                <th>Count</th>
              </tr>
            </thead>
            <tbody>
              <tr
                v-for="stat in stats.top_10_source_ips_last_24_hours"
                :key="stat.source_ip"
              >
                <td>
                  <a :href="'/requests?q=source_ip:' + stat.source_ip">{{ stat.source_ip }}</a>
                </td>
                <td>{{ stat.total_requests }}</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      <!-- Top URIs -->
      <div
        v-if="stats"
        class="stats-card"
      >
        <div class="stats-card-header">
          <i class="pi pi-link" />
          <span>Top URIs (24h)</span>
        </div>
        <div class="stats-table-wrap">
          <table>
            <thead>
              <tr>
                <th>URI</th>
                <th>Count</th>
              </tr>
            </thead>
            <tbody>
              <tr
                v-for="stat in stats.top_10_uris_last_24_hours"
                :key="stat.uri"
              >
                <td>
                  <a :href="'/requests?q=uri:' + encodeURIComponent(stat.uri)" :title="stat.uri">{{ truncateUri(stat.uri) }}</a>
                </td>
                <td>{{ stat.total_requests }}</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      <!-- Top URIs - Code Execution -->
      <div
        v-if="stats"
        class="stats-card"
      >
        <div class="stats-card-header">
          <i class="pi pi-code" />
          <span>Top URIs – Code Execution (24h)</span>
        </div>
        <div class="stats-table-wrap">
          <table>
            <thead>
              <tr>
                <th>URI</th>
                <th>Count</th>
              </tr>
            </thead>
            <tbody>
              <tr
                v-for="stat in stats.top_10_uris_code_execution"
                :key="stat.uri"
              >
                <td>
                  <a :href="'/requests?q=triage_payload_type:CODE_EXECUTION%20uri:' + encodeURIComponent(stat.uri)" :title="stat.uri">{{ truncateUri(stat.uri) }}</a>
                </td>
                <td>{{ stat.total_requests }}</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      <!-- Top URIs - Shell Command -->
      <div
        v-if="stats"
        class="stats-card"
      >
        <div class="stats-card-header">
          <i class="pi pi-terminal" />
          <span>Top URIs – Shell Command (24h)</span>
        </div>
        <div class="stats-table-wrap">
          <table>
            <thead>
              <tr>
                <th>URI</th>
                <th>Count</th>
              </tr>
            </thead>
            <tbody>
              <tr
                v-for="stat in stats.top_10_uris_shell_command"
                :key="stat.uri"
              >
                <td>
                  <a :href="'/requests?q=triage_payload_type:SHELL_COMMAND%20uri:' + encodeURIComponent(stat.uri)" :title="stat.uri">{{ truncateUri(stat.uri) }}</a>
                </td>
                <td>{{ stat.total_requests }}</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      <!-- Triage Payload Types -->
      <div
        v-if="stats"
        class="stats-card"
      >
        <div class="stats-card-header">
          <i class="pi pi-tag" />
          <span>Triage Payload Types (24h)</span>
        </div>
        <div class="stats-table-wrap">
          <table>
            <thead>
              <tr>
                <th>Payload Type</th>
                <th>Count</th>
              </tr>
            </thead>
            <tbody>
              <tr
                v-for="stat in stats.triage_payload_type_counts"
                :key="stat.triage_payload_type"
              >
                <td><a :href="'/requests?q=triage_payload_type:' +
                    encodeURIComponent(stat.triage_payload_type)">{{
                    stat.triage_payload_type }}</a></td>
                <td>{{ stat.total_requests }}</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      <!-- Malware Doughnut -->
      <div class="stats-card">
        <div class="stats-card-header">
          <i class="pi pi-exclamation-triangle" />
          <span>Malware URLs (24h)</span>
        </div>
        <div class="stats-pie-wrap">
          <PrimeChart
            type="doughnut"
            :data="malwarePieChartData"
            :options="pieChartOptions"
          />
        </div>
      </div>
    </div>
  </div>
</template>

<script>


export default {
  components: {},
  inject: ["config"],
  emits: ["require-auth"],
  data() {
    return {
      isLoading: false,
      chartData: null,
      chartOptions: null,
      chartOptions2: null,
      pieChartOptions: null,
      methodPieChartData: null,
      malwarePieChartData: null,
      rpdChartData: null, // Requests per day
      rpmChartData: null, // Requests per month
      dpdChartData: null, // Downloads per day
      stats: null,
      baseDataSet: {
        labels: [],
        datasets: [
          {
            label: "",
            data: [],
            fill: false,
            tension: 0.4,
          },
        ],
      },
    };
  },
  watch: {
    stats() {
      this.setRPDChartData();
      this.setRPMChartData();
      this.setDPDChartData();
      this.setMethodPieChartData();
      this.setMalwarePieChartData()
    },
  },
  beforeCreate() {},
  created() {},
  mounted() {
    this.loadStats();
    this.chartOptions = this.setChartOptions();
    this.chartOptions2 = this.setChartOptions();
    this.pieChartOptions = this.setPieChartOptions();
  },
  methods: {
    truncateUri(uri) {
      return uri.length > 40 ? uri.substring(0, 40) + '…' : uri;
    },
    loadStats() {
      this.isLoading = true;
      var url = this.config.backendAddress + "/stats/global";

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
            if (response.data) {
              this.stats = response.data;
              console.log(this.stats);
            }
          }
          this.isLoading = false;
        });
    },

    setRPDChartData() {
      const documentStyle = getComputedStyle(document.documentElement);

      var newStats = {
        labels: [],
        datasets: [
          {
            label: "",
            data: [],
            fill: true,
            tension: 0.1,
            borderColor: documentStyle.getPropertyValue("--p-gray-500"),
            backgroundColor: "rgba(107, 114, 128, 0.2)",
          },
        ],
      };

      for (const entry of this.stats.requests_per_day) {
        newStats.labels.push(entry.day);
        newStats.datasets[0].data.push(entry.total_entries);
      }

      newStats.labels = newStats.labels.reverse();
      newStats.datasets[0].data = newStats.datasets[0].data.reverse();

      newStats.datasets[0].label = "Requests per day";
      newStats.datasets[0].border =
        documentStyle.getPropertyValue("--p-cyan-500");
      this.rpdChartData = newStats;
    },
    setRPMChartData() {
      const documentStyle = getComputedStyle(document.documentElement);
      var newStats = {
        labels: [],
        datasets: [
          {
            label: "",
            data: [],
            fill: true,
            tension: 0.1,
            borderColor: documentStyle.getPropertyValue("--p-gray-500"),
            backgroundColor: "rgba(107, 114, 128, 0.2)",
          },
        ],
      };

      for (const entry of this.stats.requests_per_month) {
        newStats.labels.push(entry.month);
        newStats.datasets[0].data.push(entry.total_entries);
      }

      newStats.labels = newStats.labels.reverse();
      newStats.datasets[0].data = newStats.datasets[0].data.reverse();

      newStats.datasets[0].label = "Requests per month";
      newStats.datasets[0].border =
        documentStyle.getPropertyValue("--p-cyan-500");
      this.rpmChartData = newStats;
    },
    setDPDChartData() {
      const documentStyle = getComputedStyle(document.documentElement);
      var newStats = {
        labels: [],
        datasets: [
          {
            label: "",
            data: [],
            fill: true,
            tension: 0.1,
            borderColor: documentStyle.getPropertyValue('--p-gray-500'),
            backgroundColor: 'rgba(107, 114, 128, 0.2)',
          },
        ],
      };

      for (const entry of this.stats.downloads_per_day) {
        newStats.labels.push(entry.day);
        newStats.datasets[0].data.push(entry.total_entries);
      }

      newStats.labels = newStats.labels.reverse();
      newStats.datasets[0].data = newStats.datasets[0].data.reverse();

      newStats.datasets[0].label = "New downloads per day";
      newStats.datasets[0].border =
        documentStyle.getPropertyValue("--p-cyan-500");
      this.dpdChartData = newStats;
    },

    setMethodPieChartData() {
      var newData = {
        labels: [],
        datasets: [
          {
            data: [],
            backgroundColor: [
              "#8ec07c",
              "#458588",
              "#d79921",
              "#cc241d",
              "#3c3836",
              "#fe8019",
            ],
            hoverBackgroundColor: [
              "#8ec07c",
              "#458588",
              "#d79921",
              "#cc241d",
              "#3c3836",
              "#fe8019",
            ],
          },
        ],
      };

      for (const entry of this.stats.methods_last_24_hours) {
        newData.labels.push(entry.method);
        newData.datasets[0].data.push(entry.total_entries);
      }

      this.methodPieChartData = newData;
    },

    setMalwarePieChartData() {
      var newData = {
        labels: [],
        datasets: [
          {
            data: [],
            backgroundColor: [
              "#d79921",
              "#cc241d",
            ],
            hoverBackgroundColor: [
              "#d79921",
              "#cc241d",
            ],
          },
        ],
      };

      for (const entry of this.stats.malware_last_24_hours) {
        if (entry.subtype == "MALWARE_NEW") {
          newData.labels.push("New");
        } else {
          newData.labels.push("Old");
        }
        newData.datasets[0].data.push(entry.total_entries);
      }

      this.malwarePieChartData = newData;
    },

    setChartOptions() {
      const documentStyle = getComputedStyle(document.documentElement);
      const textColor = documentStyle.getPropertyValue("--p-text-color");
      const textColorSecondary = documentStyle.getPropertyValue(
        "--p-text-muted-color"
      );
      const surfaceBorder = documentStyle.getPropertyValue(
        "--p-content-border-color"
      );

      return {
        maintainAspectRatio: false,
        aspectRatio: 0.6,
        plugins: {
          legend: {
            labels: {
              color: textColor,
            },
          },
        },
        scales: {
          x: {
            ticks: {
              color: textColorSecondary,
            },
            grid: {
              color: surfaceBorder,
            },
          },
          y: {
            suggestedMin: 0,
            ticks: {
              color: textColorSecondary,
            },
            grid: {
              color: surfaceBorder,
            },
          },
        },
      };
    },

    setPieChartOptions() {
      const documentStyle = getComputedStyle(document.documentElement);
      const textColor = documentStyle.getPropertyValue("--p-text-color");

      return {
        plugins: {
          legend: {
            labels: {
              cutout: "60%",
              color: textColor,
            },
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

.stats-chart-wrap {
  padding: 1rem;
  height: 22rem;
}

.stats-chart {
  height: 100% !important;
}

.stats-pie-wrap {
  padding: 1rem;
  display: flex;
  justify-content: center;
  max-height: 280px;
}

.stats-table-wrap {
  padding: 0.75rem 1rem;
}

.stats-table-wrap table {
  width: 100%;
  border-collapse: collapse;
}

.stats-table-wrap th,
.stats-table-wrap td {
  padding: 0.4rem 0.5rem;
  font-size: 0.9rem;
}

.stats-table-wrap tbody tr:hover {
  background: var(--p-surface-50);
}
</style>
