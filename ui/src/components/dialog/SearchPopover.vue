<template>
  <PopOver ref="op">
    For detailed information on building queries, see the
    <a
      href="https://github.com/mrheinen/lophiid/blob/main/SEARCH.md"
      target="_blank"
      >documentation</a
    >. <br /><br />
    Below are the keywords specific for this page:
    <br /><br />
    <table>
      <thead>
        <tr class="tabletr">
          <th>Keyword</th>
          <th>Description</th>
          <th>Type</th>
        </tr>
      </thead>
      <tbody>
        <tr v-for="[keyword, entry] in options" :key="keyword">
          <th>{{ keyword }}</th>
          <td>{{ entry.field_doc }}</td>
          <td>{{ entry.field_type }}</td>
        </tr>
      </tbody>
    </table>
  </PopOver>
</template>

<script>
export default {
  inject: ["config"],
  props: ["modelname"],
  data() {
    return {
      options: null,
    };
  },
  methods: {
    show(event) {
      this.fetchModelDocs(this.modelname);
      this.$refs.op.toggle(event);
    },
    fetchModelDocs(modelName) {
      var url =
        this.config.backendAddress +
        this.config.datamodelDocLink +
        "?" +
        "model=" +
        modelName;
      fetch(url, {
        headers: {
          "API-Key": this.$store.getters.apiToken,
        },
      })
        .then((response) => {
          return response.json();
        })
        .then((response) => {
          if (!response) {
            this.$toast.error(response.message);
          } else {
            if (response.data != null || response.data.length > 0) {
              this.options = new Map();

              for (const key in response.data) {
                this.options.set(key, response.data[key]);
              }

            } else {
              console.log("got wrong response", response);
            }
          }
        });
    },
  },
};
</script>

<style scoped>
.tabletr {
  background-color: lightgray;
}
</style>
