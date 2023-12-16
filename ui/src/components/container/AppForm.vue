<template>
  <div>
    <div class="field">
      <input type="hidden" name="id" v-model="localApp.id" />
      <label class="label">Name</label>

      <InputText
        id="name"
        type="text"
        placeholder="App name"
        v-model="localApp.name"
      />
    </div>

    <div class="field">
      <label class="label">Version</label>
      <InputText
        id="version"
        type="text"
        placeholder="v1.1.x"
        v-model="localApp.version"
      />
    </div>

    <div class="field">
      <label class="label">Vendor</label>

      <InputText
        id="vendor"
        type="text"
        placeholder="Microfast"
        v-model="localApp.vendor"
      />
    </div>

    <div class="field">
      <label class="label">Operating system</label>

      <InputText
        id="os"
        type="text"
        placeholder="Linux"
        v-model="localApp.os"
      />
    </div>

    <div class="field">
      <label class="label">Reference link </label>
      <InputText
        id="reference"
        type="text"
        placeholder="http://..."
        v-model="localApp.link"
      />
    </div>

    <button class="button is-primary" @click="submitForm()">
      {{ localApp.id > 0 ? "Submit" : "Add" }}
    </button>
    &nbsp;
    <button class="button is-dark" @click="resetForm()">Reset</button>
    <a
      v-if="localApp.id && localApp.id > 0"
      @click.prevent="deleteContent(localApp.id)"
      href="#"
      >delete</a
    >
  </div>
</template>

<script>
export default {
  props: ["app"],
  emits: ["update-app"],
  inject: ["config"],
  data() {
    return {
      localApp: {},
    };
  },
  methods: {
    resetForm() {
      this.localApp = {};
    },
    onContentFormClicked() {
      this.$emit("open-content-form");
    },
    submitForm() {
      const appToSubmit = Object.assign({}, this.localApp);
      // Remove the added fields.
      delete appToSubmit.parsed;

      fetch(this.config.backendAddress + "/app/upsert", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(appToSubmit),
      })
        .then((response) => response.json())
        .then((response) => {
          if (response.status == this.config.backendResultNotOk) {
            this.$toast.error(response.message);
          } else {
            this.$toast.success("Saved entry");
            if (response.data) {
              if (response.data.length > 0) {
                // It was an insert.
                this.$emit("update-app", response.data[0].id);
              } else {
                // It was an update.
                this.$emit("update-app", this.localApp.id);
              }
            }
          }
        });
    },

    deleteContent(id) {
      fetch(this.config.backendAddress + "/app/delete", {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
        },
        body: "id=" + id,
      })
        .then((response) => response.json())
        .then((response) => {
          if (response.status == this.config.backendResultNotOk) {
            this.$toast.error(response.message);
          } else {
            this.$toast.success("Deleted entry");
            this.resetForm();
            this.$emit("update-app");
          }
        });
    },
  },
  watch: {
    app() {
      this.localApp = Object.assign({}, this.app);
    },
  },
  created() {
    // this.app = this.modelValue;
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
