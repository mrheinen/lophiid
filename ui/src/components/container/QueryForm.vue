<template>
  <div>
    <input type="hidden" name="id" v-model="localQuery.id" />
    <div class="card">
    <FieldSet legend="Settings" :toggleable="true">
      <div>
        <label class="label">Query</label>
        <InputText
          id="title"
          type="text"
          placeholder=""
          v-model="localQuery.query"
        />
      </div>

      <div>
        <label class="label">Description</label>
        <TextArea
          v-model="localQuery.description"
          autoResize
          rows="4"
          cols="40"
        />
      </div>
      <div>
        <label class="label">Tags</label>
        <MultiSelect
          v-model="localQuery.parsed.tags_to_apply"
          placeholder="Select tags"
          optionLabel="name"
          :options="tags"
        ></MultiSelect>
      </div>

    <br/>
    <PrimeButton
      :label="localQuery.id > 0 ? 'Submit' : 'Add'"
      @click="submitForm()"
    >
    </PrimeButton>
    &nbsp;
    <PrimeButton
      severity="secondary"
      label="Reset"
      @click="resetForm()"
    ></PrimeButton>
    &nbsp;
    <PrimeButton
      severity="danger"
      @click="requireConfirmation($event)"
      label="Delete"
    ></PrimeButton>
    </FieldSet>
    </div>

    <ConfirmPopup group="headless">
      <template #container="{ message, acceptCallback, rejectCallback }">
        <div class="bg-gray-900 text-white border-round p-3">
          <span>{{ message.message }}</span>
          <div class="flex align-items-center gap-2 mt-3">
            <PrimeButton
              icon="pi pi-check"
              label="Save"
              @click="acceptCallback"
              class="p-button-sm p-button-outlined"
            ></PrimeButton>
            <PrimeButton
              label="Cancel"
              severity="secondary"
              outlined
              @click="rejectCallback"
              class="p-button-sm p-button-text"
            ></PrimeButton>
          </div>
        </div>
      </template>
    </ConfirmPopup>
  </div>
</template>

<script>
export default {
  props: ["query"],
  emits: ["update-query", "delete-query", "require-auth"],
  inject: ["config"],
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
  methods: {
    requireConfirmation(event) {
      this.$confirm.require({
        target: event.currentTarget,
        group: "headless",
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
            this.tags = response.data;

            this.tags.forEach((tag) => {
              this.tagPerIdMap.set(tag.id, tag);
            })
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
  watch: {
    query() {
      this.localQuery = Object.assign({}, this.query);
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
    // this.app = this.modelValue;
  },
};
</script>

<style scoped>
</style>
