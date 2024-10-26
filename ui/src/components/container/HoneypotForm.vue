<template>
  <div>
    <input type="hidden" name="id" v-model="localHoneypot.id" />
    <div class="card">
    <FieldSet legend="Settings" :toggleable="true">
      <div>
        <label class="label">IP</label>
        <InputText
          id="title"
          type="text"
          placeholder=""
          v-model="localHoneypot.ip"
        />
      </div>

      <div>
        <label class="label">Default Content ID</label>
        <InputNumber
          v-model="localHoneypot.default_content_id"
          inputId="minmax"
          :useGrouping="false"
          :min="0"
          :max="65535"
        />
     &nbsp;
      </div>

      <div class="field">
        <label class="label">Authentication token</label>
        <InputText
          id="auth-token"
          type="text"
          placeholder=""
          v-model="localHoneypot.auth_token"
        />
      </div>


      <div class="field">
        <label class="label">HTTP Ports</label>

        {{ localPorts }}
      </div>

      <div class="field">
        <label class="label">HTTPS Ports</label>

        {{ localSSLPorts }}
      </div>



      <br/>
    <PrimeButton
      :label="localHoneypot.id > 0 ? 'Submit' : 'Add'"
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
  props: ["honeypot"],
  emits: ["update-honeypot", "delete-honeypot", "require-auth"],
  inject: ["config"],
  data() {
    return {
      localHoneypot: {},
      localPorts: "",
      localSSLPorts: "",
    };
  },
  methods: {
    requireConfirmation(event) {
      this.$confirm.require({
        target: event.currentTarget,
        group: "headless",
        message: "Are you sure? You cannot undo this.",
        accept: () => {
          if (this.localHoneypot.id) {
            this.deleteHoneypot(this.localHoneypot.id);
          }
        },
        reject: () => {},
      });
    },
    resetForm() {
      this.localHoneypot = {};
    },
    submitForm() {
      const honeypotToSubmit = Object.assign({}, this.localHoneypot);
      // Remove the added fields.
      delete honeypotToSubmit.parsed;

      fetch(this.config.backendAddress + "/honeypot/update", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "API-Key": this.$store.getters.apiToken,
        },
        body: JSON.stringify(honeypotToSubmit),
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
            this.$toast.success("Saved entry");
            this.$emit("update-honeypot", this.localHoneypot.id);
          }
        });
    },

    deleteHoneypot(id) {
      fetch(this.config.backendAddress + "/honeypot/delete", {
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
            this.$emit("delete-honeypot");
          }
        });
    },
  },
  watch: {
    honeypot() {
      this.localHoneypot = Object.assign({}, this.honeypot);

      this.localPorts = this.localHoneypot.ports.join(", ");
      this.localSSLPorts = this.localHoneypot.ssl_ports.join(", ");
    },
  },
  created() {
    // this.app = this.modelValue;
  },
};
</script>

<style scoped>

#auth-token {
  width: 100%;
}

</style>
