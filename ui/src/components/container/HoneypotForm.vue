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

          <br>
          <PrimeButton
            :label="localHoneypot.id > 0 ? 'Submit' : 'Add'"
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
};
</script>

<style scoped>

#auth-token {
  width: 100%;
}

</style>
