<template>
  <div>
    <input type="hidden" name="id" v-model="localTag.id" />
    <div class="card">
    <FieldSet legend="Settings" :toggleable="true">
      <div>
        <label class="label">Name</label>
        <InputText
        id="title"
        type="text"
        placeholder=""
        v-model="localTag.name"
        />
      </div>
      <div>
        <label class="label">HTML Color</label>
        <ColorPicker
          v-model="localTag.color_html"
          format="hex"
        />
      </div>
      <div>
        <label class="label">Description</label>
        <InputText
        id="description"
        type="text"
        placeholder=""
        v-model="localTag.description"
        />
      </div>

      <br/>
    <PrimeButton
      :label="localTag.id > 0 ? 'Submit' : 'Add'"
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
  props: ["tag"],
  emits: ["update-tag", "delete-tag", "require-auth"],
  inject: ["config"],
  data() {
    return {
      localTag: {},
    };
  },
  methods: {
    requireConfirmation(event) {
      this.$confirm.require({
        target: event.currentTarget,
        group: "headless",
        message: "Are you sure? You cannot undo this.",
        accept: () => {
          if (this.localTag.id) {
            this.deleteTag(this.localTag.id);
          }
        },
        reject: () => {},
      });
    },
    resetForm() {
      this.localTag = {};
    },
    submitForm() {
      const tagToSubmit = Object.assign({}, this.localTag);
      // Remove the added fields.
      delete tagToSubmit.parsed;

      fetch(this.config.backendAddress + "/tag/upsert", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "API-Key": this.$store.getters.apiToken,
        },
        body: JSON.stringify(tagToSubmit),
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
              this.$emit("update-tag", response.data[0].id);
            } else {
              this.$toast.success("Updated entry");
              this.$emit("update-tag", this.localTag.id);
            }
          }
        });
    },

    deleteTag(id) {
      fetch(this.config.backendAddress + "/tag/delete", {
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
            this.$emit("delete-tag");
          }
        });
    },
  },
  watch: {
    tag() {
      this.localTag = Object.assign({}, this.tag);
    },
  },
  created() {
    // this.app = this.modelValue;
  },
};
</script>

<style scoped></style>
