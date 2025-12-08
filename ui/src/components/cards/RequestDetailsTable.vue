<template>
  <table>
    <tbody>
      <tr>
        <th>Request ID</th>
        <td>
          {{ request.id }}
        </td>
      </tr>
      <tr>
        <th>Content ID</th>
        <td>
          <a :href="'/content?q=id:' + request.content_id">
            {{ request.content_id }}
          </a>
        </td>
      </tr>

      <tr>
        <th>Rule ID</th>
        <td>
          <a :href="'/rules?q=id:' + request.rule_id">
            {{ request.rule_id }}
          </a>
        </td>
      </tr>
      <tr>
        <th>Session ID</th>
        <td>
          <a :href="'/requests?q=session_id:' + request.session_id">
            {{ request.session_id }}
          </a>
        </td>
      </tr>
      <tr>
        <th>Honeypot IP</th>
        <td>
          <a :href="'/requests?q=honeypot_ip:' + request.honeypot_ip">
            {{ request.honeypot_ip }}
          </a>
        </td>
      </tr>
      <tr>
        <th>Honeypot port</th>
        <td>
          <a :href="'/requests?q=port:' + request.port">
            {{ request.port }}
          </a>
        </td>
      </tr>
      <tr>
        <th>Base Hash</th>
        <td>
          {{ request.base_hash }}
          <a :href="'/requests?q=base_hash:' + request.base_hash">
            <i
              class="pi pi-search"
              title="find similar requests"
            />
          </a>
        </td>
      </tr>
      <tr>
        <th>Cmp Hash</th>
        <td>
          {{ request.cmp_hash }}
          <a :href="'/requests?q=cmp_hash:' + request.cmp_hash">
            <i
              class="pi pi-search"
              title="find the same requests across hosts"
            />
          </a>
        </td>
      </tr>

      <tr v-if="request.tags">
        <th>Labels</th>
        <td>
          <div
            v-for="tag in request.tags"
            :key="tag.tag.id"
            :title="tag.tag.description"
            class="mytag"
            :style="'background-color: #' + tag.tag.color_html"
          >
            <a :href="'/requests?q=label:' + tag.tag.name">
              {{ tag.tag.name }}&nbsp;
            </a>
          </div>
        </td>
      </tr>

      <tr v-if="request.p0f_result">
        <th>Operating system</th>
        <td>{{ request.p0f_result.os_name }}</td>
      </tr>
      <tr v-if="request.p0f_result">
        <th>Operating version</th>
        <td>{{ request.p0f_result.os_version }}</td>
      </tr>
      <tr v-if="request.p0f_result">
        <th>Distance</th>
        <td>{{ request.p0f_result.distance }}</td>
      </tr>
      <tr v-if="request.p0f_result">
        <th>Link type</th>
        <td>{{ request.p0f_result.link_type }}</td>
      </tr>
      <tr
        v-if="
          request.p0f_result &&
            (calculatedUptimeDays > 0 || calculatedUptimeAndHours > 0)
        "
      >
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
    "request": {
      type: Object,
      required: true
    }
  },
  data() {
    return {
      calculatedUptimeDays: 0,
      calculatedUptimeAndHours: 0,
    };
  },

  watch: {
    request() {
      if (this.request.p0f_result) {
        this.calculatedUptimeDays = Math.round(
          this.request.p0f_result.uptime_minutes / (60 * 24)
        );
        this.calculatedUptimeAndHours = Math.round(
          (this.request.p0f_result.uptime_minutes % (60 * 24)) / 60
        );
      }
    },
  },
};
</script>

<style scoped>
th {
  width: 140px;
}
</style>
