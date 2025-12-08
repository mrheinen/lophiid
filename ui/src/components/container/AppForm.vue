<template>
  <PrimeDialog
    v-model:visible="importFormVisible"
    modal
    header="Export app tree"
  >
    <ImportAppForm @form-done="onImportDone()" />
  </PrimeDialog>


  <div v-if="localApp">
    <input
      v-model="localApp.id"
      type="hidden"
      name="id"
    >
    <div>
      <InfoCard mylabel="Settings">
        <template #default>
          <div>
            <label class="label">Name</label>
            <InputText
              id="title"
              v-model="localApp.name"
              type="text"
              placeholder=""
            />
          </div>

          <div class="field">
            <label class="label">Version</label>
            <InputText
              id="version"
              v-model="localApp.version"
              type="text"
              placeholder="v1.1.x"
            />
          </div>

          <div class="field">
            <label class="label">Vendor</label>

            <InputText
              id="vendor"
              v-model="localApp.vendor"
              type="text"
              placeholder="Microfast"
            />
          </div>

          <div class="field">
            <label class="label">Operating system</label>

            <InputText
              id="os"
              v-model="localApp.os"
              type="text"
              placeholder="Linux"
            />
          </div>

          <div class="field">
            <label class="label">Reference link </label>
            <InputText
              id="reference"
              v-model="localApp.link"
              type="text"
              placeholder="http://..."
            />
          </div>

          <div>
            <label class="label">CVEs</label>
            <TextArea
              v-model="cves"
              rows="4"
              cols="25"
            />
          </div>

          <div class="field">
            <label class="label">UUID</label>
            <InputText
              id="uuid"
              v-model="localApp.ext_uuid"
              type="text"
              disabled
              placeholder="The UUID of the app"
            />
          </div>

          <br>

          <PrimeButton
            :label="localApp.id > 0 ? 'Submit' : 'Add'"
            @click="submitForm()"
          />
    &nbsp;
          <PrimeButton
            severity="secondary"
            label="New"
            @click="resetForm()"
          />
    &nbsp;
          <PrimeButton
            severity="danger"
            label="Delete"
            @click="requireConfirmation($event)"
          />
    &nbsp;
          <PrimeButton
            severity="secondary"
            label="Export"
            @click="exportApp(localApp.id)"
          />

    &nbsp;
          <PrimeButton
            severity="secondary"
            label="Import"
            @click="showImportForm()"
          />
        </template>
      </InfoCard>
    </div>

    <ConfirmPopup group="headless">
      <template #container="{ message, acceptCallback, rejectCallback }">
        <div class="bg-gray-900 text-white border-round p-3">
          <span>{{ message.message }}</span>
          <div class="flex align-items-center gap-2 mt-3">
            <PrimeButton
              icon="pi pi-check"
              label="Save"
              class="p-button-sm p-button-outlined"
              @click="acceptCallback"
            />
            <PrimeButton
              label="Cancel"
              severity="secondary"
              outlined
              class="p-button-sm p-button-text"
              @click="rejectCallback"
            />
          </div>
        </div>
      </template>
    </ConfirmPopup>
  </div>
</template>

<script>

import ImportAppForm from './ImportAppForm.vue';

function isCVE(str) {
  const cveRegex = /^CVE-\d{4}-\d{4,7}$/i;
  return cveRegex.test(str);
}

export default {
  components: {
    ImportAppForm,
  },
  inject: ["config"],
  props: {
    "app": {
      type: Object,
      required: true
    },
  },
  emits: ["update-app", "delete-app", "require-auth"],
  data() {
    return {
      cves: "",
      localApp: {},
      importFormVisible: false,
    };
  },
  watch: {
    app() {
      this.localApp = Object.assign({}, this.app);

      var tmpCves = "";
      this.cves = "";
      if (this.localApp.cves) {
        var prefix = "";
        this.localApp.cves.forEach((cve) => {
          tmpCves += prefix + cve;
          prefix = "\n";
        });
        this.cves = tmpCves;
      }
    },
  },
  created() {
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
      this.cves = "";
    },
    onImportDone() {
      this.$emit("update-app");
      this.importFormVisible = false;
    },
    showImportForm() {
      this.importFormVisible = true;
    },
    submitForm() {
      const appToSubmit = Object.assign({}, this.localApp);
      // Remove the added fields.
      delete appToSubmit.parsed;

      appToSubmit.cves = []
      if (this.cves != "") {
        var allCves = this.cves.split("\n");
        if (!allCves || allCves.length == 0) {
          if (!isCVE(this.cves)) {
            this.$toast.error("Please provide a valid CVE");
            return
          }
          allCves.push(this.cves);
        }

        allCves.forEach((cve) => {
          if (cve != "") {
            if (!isCVE(cve)) {
              this.$toast.error("Please provide valid CVEs");
              return
            }
            appToSubmit.cves.push(cve);
          }
        });
      }

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
            var filename = response.data['vendor'] + '-' + response.data['name'] + '-' + response.data['version'] + '.yaml';
            const blob = new Blob([response.data['yaml']], { type: 'application/yaml' })
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
