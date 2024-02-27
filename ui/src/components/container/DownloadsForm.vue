<template>
  <div>
    <input type="hidden" name="id" v-model="localDownload.id" />
    <div class="card">
    <FieldSet legend="Download details" :toggleable="true">
      <table>
        <tbody>
          <tr>
            <th>First seen</th>
            <td>{{localDownload.parsed.created_at}}</td>
          </tr>
          <tr>
            <th>Last seen</th>
            <td>{{localDownload.parsed.last_seen_at}}</td>
          </tr>
          <tr>
            <th>Times seen</th>
            <td>{{localDownload.times_seen}}</td>
          </tr>
          <tr>
            <th>Size byte</th>
            <td>{{localDownload.size}}</td>
          </tr>
          <tr>
            <th>URL Original</th>
            <td>{{localDownload.original_url}}</td>
          </tr>
          <tr v-if="localDownload.original_url != localDownload.used_url">
            <th>URL Used</th>
            <td>{{localDownload.used_url}} (Host: {{localDownload.host}})</td>
          </tr>
          <tr>
            <th>SHA 256</th>
            <td>{{localDownload.sha256sum}}</td>
          </tr>

        </tbody>
      </table>
    </FieldSet>
    </div>
  </div>
</template>

<script>

export default {
  components: {
  },
  props: ["download"],
  emits: ["require-auth"],
  inject: ["config"],
  data() {
    return {
      localDownload: {
        parsed: {},

      },
    };
  },
  methods: {
    exportDownload(id) {
      fetch(this.config.backendAddress + "/download/export", {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          "API-Key": this.$store.getters.apiToken,
        },
        body: "id=" + id,
      })
       .then((response) => {
          if (response.status == 403) {
            this.$emit('require-auth');
            return null;
          } else {
            return response.json()
          }
        })
        .then((response) => {
          if (!response) {
            return;
          }
          if (response.status == this.config.backendResultNotOk) {
            this.$toast.error("Could not export download");
          } else {
            var filename = "changeme.txt";
            const blob = new Blob([JSON.stringify(response.data)], { type: 'application/binary' })
            const link = document.createElement('a');
            link.href = URL.createObjectURL(blob);
            link.download = filename;
            link.click();
            URL.revokeObjectURL(link.href);
            link.remove();
            this.$toast.success("Exported download");
          }
        });
    },
  },
  watch: {
    download() {
      this.localDownload = Object.assign({}, this.download);
    },
  },
  created() {
  },
};
</script>

<style scoped>
.app {
  width: 100%;
  height: 400px;
}

.description {
  width: 100%;
  height: 140px;
}
</style>
