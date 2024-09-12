<template>

  <PrimeDialog v-model:visible="importFormVisible" modal header="Export app tree">
    <ImportAppForm @form-done="onImportDone()"></ImportAppForm>
  </PrimeDialog>


  <div>
    <input type="hidden" name="id" v-model="localApp.id" />
    <div class="card">
    <FieldSet legend="Settings" :toggleable="true">
      <div>
        <label class="label">Name</label>
        <InputText
          id="title"
          type="text"
          placeholder=""
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

      <div class="field">
        <label class="label">Version</label>
        <InputNumber
        id="version"
        type="text"
        placeholder="The version of the app"
        v-model="localApp.ext_version"
        />
      </div>

      <div class="field">
        <label class="label">UUID</label>
        <InputText
        id="uuid"
        type="text"
        disabled
        placeholder="The UUID of the app"
        v-model="localApp.ext_uuid"
        />
      </div>

      <br/>

    <PrimeButton
      :label="localApp.id > 0 ? 'Submit' : 'Add'"
      @click="submitForm()"
    >
    </PrimeButton>
    &nbsp;
    <PrimeButton
      severity="secondary"
      label="New"
      @click="resetForm()"
    ></PrimeButton>
    &nbsp;
    <PrimeButton
      severity="danger"
      @click="requireConfirmation($event)"
      label="Delete"
    ></PrimeButton>
    &nbsp;
    <PrimeButton
      severity="secondary"
      @click="exportApp(localApp.id)"
      label="Export"
    ></PrimeButton>

    &nbsp;
    <PrimeButton
      severity="secondary"
      @click="showImportForm()"
      label="Import"
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

import ImportAppForm from './ImportAppForm.vue';

export default {
  components: {
    ImportAppForm,
  },
  props: ["app"],
  emits: ["update-app", "delete-app", "require-auth"],
  inject: ["config"],
  data() {
    return {
      localApp: {},
      importFormVisible: false,
    };
  },
  methods: {
    requireConfirmation(event) {
      this.$confirm.require({
        target: event.currentTarget,
        group: "headless",
        message: "Are you sure? You cannot undo this.",
        accept: () => {
          if (this.localApp.id) {
            this.deleteApp(this.localApp.id);
          }
        },
        reject: () => {},
      });
    },
    resetForm() {
      this.localApp = {};
    },
    onImportDone() {
      this.$emit("update-app");
      this.importFormVisible = false;
    },
    showImportForm() {
      this.importFormVisible = true;
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
          "API-Key": this.$store.getters.apiToken,
        },
        body: JSON.stringify(appToSubmit),
      })
        .then((response) => {
          if (response.status == 403) {
            this.$emit('require-auth');
          } else {
            return response.json()
          }
        })
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

    deleteApp(id) {
      fetch(this.config.backendAddress + "/app/delete", {
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
          } else {
            return response.json()
          }
        })
        .then((response) => {
          if (response.status == this.config.backendResultNotOk) {
            this.$toast.error(response.message);
          } else {
            this.$toast.success("Deleted entry");
            this.resetForm();
            this.$emit("delete-app");
          }
        });
    },
    exportApp(id) {
      fetch(this.config.backendAddress + "/app/export", {
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
          } else {
            return response.json()
          }
        })
        .then((response) => {
          if (response.status == this.config.backendResultNotOk) {
            this.$toast.error("Could not export app");
          } else {
            var filename = response.data.app['name'] + '-' + response.data.app['version'];
            const blob = new Blob([JSON.stringify(response.data)], { type: 'application/json' })
            const link = document.createElement('a');
            link.href = URL.createObjectURL(blob);
            link.download = filename;
            link.click();
            URL.revokeObjectURL(link.href);
            link.remove();
            this.$toast.success("Exported app");
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
