<template>
  <div>
    <input
      v-model="localEvent.id"
      type="hidden"
      name="id"
    >
    <div>
      <InfoCard mylabel="Event details">
        <template #default>
          <table>
            <tbody>
              <tr>
                <th>IP</th>
                <td>{{ localEvent.ip }}</td>
              </tr>
              <tr>
                <th>Type</th>
                <td>{{ localEvent.type }}</td>
              </tr>
              <tr v-if="localEvent.subtype">
                <th>Sub Type</th>
                <td>{{ localEvent.subtype }}</td>
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
              <tr v-if="localEvent.source_ref2 && localEvent.source_ref_type2 == 'PARAMETER'">
                <th>Target Parameter</th>
                <td>{{ localEvent.source_ref2 }}</td>
              </tr>
            </tbody>
          </table>
        </template>
      </InfoCard>
    </div>
  </div>
</template>

<script>
export default {
  inject: ["config"],
  props: {
    "event": {
      type: Object,
      required: true
    }
  },
  emits: ["update-event", "require-auth"],
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
  watch: {
    event() {
      this.localEvent = Object.assign({}, this.event);
    },
  },
  created() {
    this.localEvent = Object.assign({}, this.baseEvent);
  },
  methods: {
  },
};
</script>

<style scoped>
</style>
