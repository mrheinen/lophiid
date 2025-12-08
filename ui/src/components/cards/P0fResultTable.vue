<template>
  <table>
    <tbody>
      <tr>
        <th>Operating system</th>
        <td>{{ p0f.os_name }}</td>
      </tr>
      <tr>
        <th>Operating version</th>
        <td>{{ p0f.os_version }}</td>
      </tr>
      <tr>
        <th>OS matching quality</th>
        <td>{{ osMatchQuality }}</td>
      </tr>
      <tr>
        <th>Distance</th>
        <td>{{ p0f.distance }}</td>
      </tr>
      <tr>
        <th>Link type</th>
        <td>{{ p0f.link_type }}</td>
      </tr>
      <tr v-if="calculatedUptimeDays > 0 || calculatedUptimeAndHours > 0">
        <th>Uptime</th>
        <td>
          {{ calculatedUptimeDays }} days and
          {{ calculatedUptimeAndHours }} hours
        </td>
      </tr>
    </tbody>
  </table>
</template>

<script>
export default {
  props: {
    label: {
      type: String,
      required: true,
    },
    p0f: {
      type: Object,
      required: true,
    },
  },
  data() {
    return {
      calculatedUptimeDays: 0,
      calculatedUptimeAndHours: 0,
      osMatchQuality: "",
    };
  },
  watch: {
    p0f() {
      this.calculatedUptimeDays = Math.round(
        this.p0f.uptime_minutes / (60 * 24)
      );
      this.calculatedUptimeAndHours = Math.round(
        (this.p0f.uptime_minutes % (60 * 24)) / 60
      );

      switch (this.p0f.os_match_quality) {
        case 0:
          this.osMatchQuality = "good";
          break;
        case 1:
          this.osMatchQuality = "fuzzy";
          break;
        case 2:
          this.osMatchQuality = "generic";
          break;
        case 3:
          this.osMatchQuality = "generic/fuzzy";
          break;
        default:
          this.osMatchQuality = "unknown: BUG!";
          break;
      }
    },
  },
  methods: {},
};
</script>

<style scoped>
table {
  border-collapse: collapse;
}

th,
td {
  padding-top: 2px;
  padding-bottom: 2px;
  padding-right: 8px;
}

th {
  color: #616060;
}

.pointer {
  cursor: pointer;
}
</style>
