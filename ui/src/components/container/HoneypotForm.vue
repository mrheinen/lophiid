<template>
  <div>
    <input type="hidden" name="id" v-model="localHoneypot.id" />
    <FieldSet legend="Settings" :toggleable="true">
      <div>
        <label class="label">IP</label>
        <InputText
          id="title"
          type="text"
          placeholder=""
          disabled="true"
          v-model="localHoneypot.ip"
        />
      </div>

      <div>
          <label class="label">Content ID</label>
          <InputNumber
            v-model="localHoneypot.default_content_id"
            inputId="minmax"
            :useGrouping="false"
            :min="0"
            :max="65535"
          />
          &nbsp;
        </div>

    </FieldSet>

    <PrimeButton
      :label="localHoneypot.id > 0 ? 'Submit' : 'Add'"
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
  emits: ["update-honeypot"],
  inject: ["config"],
  data() {
    return {
      localHoneypot: {},
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
        },
        body: JSON.stringify(honeypotToSubmit),
      })
        .then((response) => response.json())
        .then((response) => {
          if (response.status == this.config.backendResultNotOk) {
            this.$toast.error(response.message);
          } else {
            this.$toast.success("Saved entry");
            this.$emit("update-honeypot");
          }
        });
    },

    deleteHoneypot(id) {
      fetch(this.config.backendAddress + "/honeypot/delete", {
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
            this.$emit("update-honeypot");
          }
        });
    },
  },
  watch: {
    honeypot() {
      this.localHoneypot = Object.assign({}, this.honeypot);
    },
  },
  created() {
    // this.app = this.modelValue;
  },
};
</script>

<style scoped>
</style>
