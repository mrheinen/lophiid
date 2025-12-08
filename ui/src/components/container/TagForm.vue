<template>
  <div>
    <input
      v-model="localTag.id"
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
              v-model="localTag.name"
              type="text"
              placeholder=""
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
              v-model="localTag.description"
              type="text"
              placeholder=""
            />
          </div>

          <br>
          <PrimeButton
            :label="localTag.id > 0 ? 'Submit' : 'Add'"
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
    "tag": {
      type: Object,
      required: true
    },
  },
  emits: ["update-tag", "delete-tag", "require-auth"],
  data() {
    return {
      localTag: {},
    };
  },
  watch: {
    tag() {
      this.localTag = Object.assign({}, this.tag);
    },
  },
  created() {
    // this.app = this.modelValue;
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
};
</script>

<style scoped></style>
