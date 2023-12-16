<template>
  <div>
    <table>
      <thead>
        <th>Name</th>
        <th>Value</th>
      </thead>
      <tbody>
        <tr v-if="localRequest.user_agent">
          <td>User agent</td>
          <td>{{ localRequest.user_agent }}</td>
        </tr>

        <tr v-if="localRequest.referer">
          <td>Referer</td>
          <td>{{ localRequest.referer }}</td>
        </tr>

      </tbody>
    </table>
    <div class="pre-text">
      <pre v-if="localRequest.raw">{{ localRequest.raw }}</pre>
    </div>
  </div>
</template>

<script>
export default {
  props: ["request"],
  inject: ["config"],
  data() {
    return {
      localRequest: {
        parsed: {},
      },
    };
  },
  watch: {
    request() {
      this.localRequest = Object.assign({}, this.request);
    },
  },
  created() {},
};
</script>

<style scoped>
pre {
  height: auto;
  max-height: 400px;
  overflow: auto;
  background-color: #eeeeee;
  word-break: normal !important;
  word-wrap: normal !important;
  white-space: pre !important;
}

#pre_text {
  height: auto;
  width: 700px;
  max-height: 200px;
  overflow: auto;
  /*overflow-y: none;*/
  background-color: #eeeeee;
}
</style>
