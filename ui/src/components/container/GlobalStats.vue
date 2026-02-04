<template>
  <div class="flex flex-row">
    <div class="basis-1/5" />
    <div
      class="basis-3/5"
      style="margin-left: 15px"
    >
      <div class="grid grid-cols-2 gap-4">
        <div class="rounded overflow-hidden shadow-lg">
          <PrimeChart
            type="line"
            :data="rpmChartData"
            :options="chartOptions2"
            class="h-[30rem]"
          />
        </div>

        <div class="rounded overflow-hidden shadow-lg">
          <PrimeChart
            type="line"
            :data="rpdChartData"
            :options="chartOptions"
            class="h-[30rem]"
          />
        </div>

        <div class="rounded overflow-hidden shadow-lg">
          <PrimeChart
            type="line"
            :data="dpdChartData"
            :options="chartOptions2"
            class="h-[30rem]"
          />
        </div>

        <div class="rounded overflow-hidden shadow-lg">
          <div class="grid grid-cols-2 gap-4">
            <div class="rounded overflow-hidden shadow-lg">
              Method count last 24 hours
              <PrimeChart
                type="doughnut"
                :data="methodPieChartData"
                :options="pieChartOptions"
                class=""
              />
            </div>

            <div class="rounded overflow-hidden shadow-lg">
              Unique malware URLs seen last 24 hours
              <PrimeChart
                type="doughnut"
                :data="malwarePieChartData"
                :options="pieChartOptions"
                class=""
              />
            </div>
          </div>
        </div>
        <div v-if="stats" class="rounded overflow-hidden shadow-lg">
          <table>
            <thead>
              <tr>
                <th>Source IP</th>
                <th>Amount</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="stat in stats.top_10_source_ips_last_24_hours" :key="stat.source_ip">
                <td><a :href="'/requests?q=source_ip:' + stat.source_ip">{{ stat.source_ip }}</a></td>
                <td>{{ stat.total_requests }}</td>
              </tr>
            </tbody>
          </table>
        </div>
        <div v-if="stats" class="rounded overflow-hidden shadow-lg">
          <table>
            <thead>
              <tr>
                <th>URI</th>
                <th>Amount</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="stat in stats.top_10_uris_last_24_hours" :key="stat.uri">
                <td><a :href="'/requests?q=uri:' + encodeURIComponent(stat.uri)">{{ stat.uri }}</a></td>
                <td>{{ stat.total_requests }}</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>
    <div class="basis-1/5" />
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
#date {
  width: 170px;
}
.table tr.is-selected {
  background-color: #4e726d;
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

.p-inputtext {
  width: 100%;
}
</style>
