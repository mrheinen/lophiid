<template>
  <PopOver ref="op">
    <div class="popover-content">
      <p class="popover-hint">
        See the
        <a
          href="https://github.com/mrheinen/lophiid/blob/main/SEARCH.md"
          target="_blank"
        >documentation</a> for query syntax. Keywords for this page:
      </p>
      <table class="popover-table">
        <thead>
          <tr>
            <th>Keyword</th>
            <th>Description</th>
            <th>Type</th>
          </tr>
        </thead>
        <tbody>
          <tr
            v-for="[keyword, entry] in options"
            :key="keyword"
          >
            <td class="popover-keyword">{{ keyword }}</td>
            <td>{{ entry.field_doc }}</td>
            <td class="popover-type">{{ entry.field_type }}</td>
          </tr>
        </tbody>
      </table>
    </div>
  </PopOver>
</template>

<script>
export default {
  inject: ["config"],
  props: {
    "modelname": {
      type: String,
      required: true
    }
  },
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
.popover-content {
  max-width: 600px;
  max-height: 400px;
  overflow: auto;
}

.popover-hint {
  margin: 0 0 0.75rem 0;
  font-size: 0.9rem;
  color: var(--p-text-muted-color);
}

.popover-table {
  width: 100%;
  border-collapse: collapse;
  font-size: 0.85rem;
}

.popover-table thead th {
  background: var(--p-surface-100);
  padding: 0.4rem 0.6rem;
  text-align: left;
  font-weight: 600;
  border-bottom: 1px solid var(--p-surface-200);
}

.popover-table tbody td {
  padding: 0.35rem 0.6rem;
  border-bottom: 1px solid var(--p-surface-100);
}

.popover-table tbody tr:hover {
  background: var(--p-surface-50);
}

.popover-keyword {
  font-weight: 600;
  font-family: monospace;
  color: var(--p-primary-600);
  white-space: nowrap;
}

.popover-type {
  color: var(--p-text-muted-color);
  font-style: italic;
  white-space: nowrap;
}
</style>
