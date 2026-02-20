<template>
  <div>
    <input
      v-model="localQuery.id"
      type="hidden"
      name="id"
    >
    <div>
      <InfoCard mylabel="Settings">
        <template #default>
          <div>
            <label class="label">Query</label>
            <InputText
              id="title"
              v-model="localQuery.query"
              type="text"
              placeholder=""
            />
          </div>

          <div>
            <label class="label">Description</label>
            <TextArea
              v-model="localQuery.description"
              rows="4"
              cols="40"
            />
          </div>
          <div>
            <label class="label">Labels</label>
            <MultiSelect
              v-model="localQuery.parsed.tags_to_apply"
              placeholder="Select labels"
              option-label="name"
              :options="tags"
            />
          </div>

          <div class="flex gap-2 mt-3">
            <PrimeButton
              :label="localQuery.id > 0 ? 'Submit' : 'Add'"
              icon="pi pi-check"
              @click="submitForm()"
            />
            <PrimeButton
              severity="secondary"
              label="New"
              icon="pi pi-plus"
              @click="resetForm()"
            />
            <PrimeButton
              severity="danger"
              label="Delete"
              icon="pi pi-trash"
              @click="requireConfirmation($event)"
            />
          </div>
        </template>
      </InfoCard>
    </div>

    <ConfirmPopup />
  </div>
</template>

<script>
export default {
  inject: ["config"],
  props: {
    "query": {
      type: Object,
      required: true
    }
  },
  emits: ["update-query", "delete-query", "require-auth"],
  data() {
    return {
      localQuery: {
      },
      baseQuery: {
        parsed: {
          tags_to_apply: [],
        },
      },
      tags: [],
      tagPerIdMap: new Map(),
    };
  },
  watch: {
    query() {
      this.localQuery = JSON.parse(JSON.stringify(this.query));
      this.localQuery.parsed = {};
      this.localQuery.parsed.tags_to_apply = []

      if (this.localQuery.tags_to_apply) {
        this.localQuery.tags_to_apply.forEach((qtag) => {
          this.localQuery.parsed.tags_to_apply.push(this.tagPerIdMap.get(qtag.tag_id));
        })
      }
    },
  },
  created() {
    this.localQuery = Object.assign({}, this.baseQuery);
    this.getAllTags();
  },
  methods: {
    requireConfirmation(event) {
      this.$confirm.require({
        target: event.currentTarget,
        message: "Are you sure? You cannot undo this.",
        accept: () => {
          if (this.localQuery.id) {
            this.deleteQuery(this.localQuery.id);
          }
        },
        reject: () => {},
      });
    },
    resetForm() {
      this.localQuery = Object.assign({}, this.baseQuery);
    },
    getAllTags() {
      fetch(this.config.backendAddress + "/tag/segment?offset=0&limit=1000&q=", {
        method: "GET",
        headers: {
          "Content-Type": "application/json",
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
          if (!response){
            return;
          }
          if (response.status == this.config.backendResultNotOk) {
            this.$toast.error(response.message);
          } else {
            if (response.data) {
              this.tags = response.data;
              response.data.forEach((tag) => {
                this.tagPerIdMap.set(tag.id, tag);
              })
            }
          }
        });
    },
    submitForm() {
      const queryToSubmit = Object.assign({}, this.localQuery);
      queryToSubmit.tags_to_apply = [];
      queryToSubmit.parsed.tags_to_apply.forEach((tag) => {
        queryToSubmit.tags_to_apply.push({
          tag_id: tag.id,
        });
      })
      // Remove the added fields.
      delete queryToSubmit.parsed;

      fetch(this.config.backendAddress + "/storedquery/upsert", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "API-Key": this.$store.getters.apiToken,
        },
        body: JSON.stringify(queryToSubmit),
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
            return;
          }
          if (response.status == this.config.backendResultNotOk) {
            this.$toast.error(response.message);
          } else {
            if (response.data && response.data.length > 0) {
              this.$toast.success("Added entry");
              this.$emit("update-query", response.data[0].id);
            } else {
              this.$toast.success("Updated entry");
              this.$emit("update-query", this.localQuery.id);
            }
          }
        });
    },

    deleteQuery(id) {
      fetch(this.config.backendAddress + "/storedquery/delete", {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          "API-Key": this.$store.getters.apiToken,
        },
        body: "id=" + id,
      })
        .then((response) => {
          if (response.status == 403) {
            this.$emit("require-auth");
          } else {
            return response.json();
          }
        })
        .then((response) => {
          if (response.status == this.config.backendResultNotOk) {
            this.$toast.error(response.message);
          } else {
            this.$toast.success("Deleted entry");
            this.resetForm();
            this.$emit("delete-query");
          }
        });
    },
  },
};
</script>

<style scoped>
:deep(.p-inputtext),
:deep(.p-textarea),
:deep(.p-multiselect) {
  width: 100%;
}
</style>
