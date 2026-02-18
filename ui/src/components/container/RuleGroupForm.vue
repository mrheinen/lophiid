<template>
  <div>
    <input
      v-model="localRuleGroup.id"
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
              v-model="localRuleGroup.name"
              type="text"
              placeholder=""
            />
          </div>

          <br>
          <PrimeButton
            :label="localRuleGroup.id > 0 ? 'Submit' : 'Add'"
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
export default {
  inject: ["config"],
  props: {
    "rulegroup": {
      type: Object,
      required: true
    },
  },
  emits: ["update-rule-group", "delete-rule-group", "require-auth"],
  data() {
    return {
      localRuleGroup: {},
    };
  },
  watch: {
    rulegroup() {
      this.localRuleGroup = Object.assign({}, this.rulegroup);
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
          if (this.localRuleGroup.id) {
            this.deleteRuleGroup(this.localRuleGroup.id);
          }
        },
        reject: () => {},
      });
    },
    resetForm() {
      this.localRuleGroup = {};
    },
    submitForm() {
      const ruleGroupToSubmit = Object.assign({}, this.localRuleGroup);
      // Remove the added fields.
      delete ruleGroupToSubmit.parsed;

      fetch(this.config.backendAddress + "/rulegroup/upsert", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "API-Key": this.$store.getters.apiToken,
        },
        body: JSON.stringify(ruleGroupToSubmit),
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
            if (response.data && response.data.length > 0) {
              this.$toast.success("Added entry");
              this.$emit("update-rule-group", response.data[0].id);
            } else {
              this.$toast.success("Updated entry");
              this.$emit("update-rule-group", this.localRuleGroup.id);
            }
          }
        });
    },

    deleteRuleGroup(id) {
      fetch(this.config.backendAddress + "/rulegroup/delete", {
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
            this.$emit("delete-rule-group");
          }
        });
    },
  },
};
</script>

<style scoped></style>
