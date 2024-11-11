<template>
  <div>
    <input type="hidden" name="id" v-model="localEvent.id" />
    <div>
      <FieldSet legend="Event details" :toggleable="false">
        <table>
          <tbody>
            <tr>
              <th>IP</th>
              <td>{{ localEvent.ip }}</td>
            </tr>
            <tr>
              <th>Type</th>
              <td>{{ localEvent.type}}</td>
            </tr>
            <tr v-if="localEvent.subtype">
              <th >Sub Type</th>
              <td>{{ localEvent.subtype}}</td>
            </tr>
            <tr v-if="localEvent.domain">
              <th>Domain</th>
              <td>{{ localEvent.domain }}</td>
            </tr>
            <tr v-if="localEvent.details">
              <th>Details</th>
              <td>{{ localEvent.details }}</td>
            </tr>
            <tr v-if="localEvent.request_id">
              <th>Request ID</th>
              <td>{{ localEvent.request_id }}</td>
            </tr>

          </tbody>
        </table>

      </FieldSet>
    </div>
  </div>
</template>

<script>
export default {
  props: ["event"],
  emits: ["update-event", "require-auth"],
  inject: ["config"],
  data() {
    return {
      localEvent: {
      },
      baseEvent: {
      },
      tags: [],
      tagPerIdMap: new Map(),
    };
  },
  methods: {
  },
  watch: {
    event() {
      this.localEvent = Object.assign({}, this.event);
    },
  },
  created() {
    this.localEvent = Object.assign({}, this.baseEvent);
  },
};
</script>

<style scoped>
</style>
