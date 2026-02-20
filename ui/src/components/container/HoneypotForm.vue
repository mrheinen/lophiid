<template>
  <div>
    <input
      v-model="localHoneypot.id"
      type="hidden"
      name="id"
    >
    <div>
      <InfoCard mylabel="Settings">
        <template #default>
          <div>
            <label class="label">IP</label>
            <InputText
              id="title"
              v-model="localHoneypot.ip"
              type="text"
              placeholder=""
            />
          </div>

          <div>
            <label class="label">Default Content ID</label>
            <InputNumber
              v-model="localHoneypot.default_content_id"
              input-id="minmax"
              :use-grouping="false"
              :min="0"
              :max="65535"
            />
          &nbsp;
          </div>

          <div class="field">
            <label class="label">Authentication token</label>
            <InputText
              id="auth-token"
              v-model="localHoneypot.auth_token"
              type="text"
              placeholder=""
            />
          </div>


          <div
            v-if="localPorts"
            class="field"
          >
            <label class="label">HTTP Ports</label>

            {{ localPorts }}
          </div>

          <div
            v-if="localSSLPorts"
            class="field"
          >
            <label class="label">HTTPS Ports</label>

            {{ localSSLPorts }}
          </div>

          <label class="label">Rule Group</label>
          <RuleGroupSelector v-model="localHoneypot.rule_group_id" />

          <div class="flex gap-2 mt-3">
            <PrimeButton
              :label="localHoneypot.id > 0 ? 'Submit' : 'Add'"
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

import RuleGroupSelector from "../RuleGroupSelector.vue";

export default {
  components: {
    RuleGroupSelector,
  },
  inject: ["config"],
  props: {
    "honeypot": {
      type: Object,
      required: true
    },
  },
  emits: ["update-honeypot", "delete-honeypot", "require-auth"],
  data() {
    return {
      localHoneypot: {},
      localPorts: "",
      localSSLPorts: "",
    };
  },
  watch: {
    honeypot() {
      this.localHoneypot = Object.assign({}, this.honeypot);

      if (this.localHoneypot.ports) {
        this.localPorts = this.localHoneypot.ports.join(", ");
      }
      if (this.localHoneypot.ssl_ports) {
        this.localSSLPorts = this.localHoneypot.ssl_ports.join(", ");
      }
    },
  },
  created() {
  },
  methods: {
    requireConfirmation(event) {
      this.$confirm.require({
        target: event.currentTarget,
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
};
</script>

<style scoped>

#auth-token {
  width: 100%;
}

</style>
