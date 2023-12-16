<template>
  <div>
    <input type="hidden" name="id" v-model="localRule.id" />
    <div class="card">
      <FieldSet legend="Settings" :toggleable="true">

        <div>
          <label class="label">Path</label>
          <InputText
          id="title"
          type="text"
          placeholder=""
          v-model="localRule.path"
          />
        </div>

        <div>
          <label class="label">Content ID</label>
          <InputNumber
          v-model="localRule.content_id"
          inputId="minmax"
          :useGrouping="false"
          :min="0"
          :max="65535"
          />
          &nbsp;
          <i @click="onContentFormOpen()" class="pi pi-plus-circle"></i>
        </div>

        <div>
          <label class="label">App ID</label>
          <DropDown
          v-model="localRule.app_id"
          :options="appValues"
          optionLabel="label"
          optionValue="value"
          placeholder="Select app"
          class="w-full md:w-14rem"
          />

          &nbsp;
          <i @click="onAppFormOpen()" class="pi pi-plus-circle"></i>
        </div>
      </FieldSet>
<!--
    </div>

    <br/>
    <div class="card">
 -->
      <FieldSet legend="Advanced settings" :toggleable="true" :collapsed="true">

        <div>
          <label class="label">Body</label>
          <InputText
          id="title"
          type="text"
          placeholder=""
          v-model="localRule.body"
          />
        </div>

        <div>
          <label class="label">Port</label>
          <InputNumber
          v-model="localRule.port"
          inputId="minmax"
          :useGrouping="false"
          :min="0"
          :max="65535"
          />
        </div>

        <div class="columns">
          <div class="column">
            <div class="field">
              <label class="label">HTTP Method</label>
              <ListBox
              v-model="localRule.method"
              :options="config.contentRuleHTTPMethods"
              class="w-full md:w-14rem"
              />
            </div>
          </div>
          <div class="column">
            <div class="field">
              <label class="label">Path matching</label>
              <ListBox
              v-model="localRule.path_matching"
              :options="config.backendMatchingMethods"
              class="w-full md:w-14rem"
              />
            </div>
          </div>
          <div class="column">
            <div class="field">
              <label class="label">Body matching</label>
              <ListBox
              v-model="localRule.body_matching"
              :options="config.backendMatchingMethods"
              class="w-full md:w-14rem"
              />
            </div>
          </div>
        </div>
      </FieldSet>
    <br/>
    <PrimeButton :label="localRule.id > 0 ? 'Submit' : 'Add'"  @click="submitForm()">
    </PrimeButton>
    &nbsp;
    <PrimeButton severity="secondary" label="Reset" @click="resetForm()"></PrimeButton>
    &nbsp;
    <PrimeButton  severity="danger" @click="requireConfirmation($event)" label="Delete"></PrimeButton>
    </div>

        <ConfirmPopup group="headless">
        <template #container="{ message, acceptCallback, rejectCallback }">
            <div class="bg-gray-900 text-white border-round p-3">
                <span>{{ message.message }}</span>
                <div class="flex align-items-center gap-2 mt-3">
                    <PrimeButton icon="pi pi-check" label="Save" @click="acceptCallback"
                    class="p-button-sm p-button-outlined"></PrimeButton>
                    <PrimeButton label="Cancel" severity="secondary" outlined @click="rejectCallback"
                    class="p-button-sm p-button-text"></PrimeButton>
                </div>
            </div>
        </template>
    </ConfirmPopup>





  </div>
</template>

<script>

export default {
  props: ["rule", "contentid", "appid"],
  emits: ["update-rule", "delete-rule", "content-form-open", "app-form-open"],
  inject: ["config"],
  data() {
    return {
     localRule: {
        path_matching: "exact",
        body_matching: "exact",
        method: "ANY",
     },
      appValues: [],
    };
  },
  methods: {
    onContentFormOpen() {
      this.$emit("content-form-open")
    },
    onAppFormOpen() {
      this.$emit("app-form-open")
    },
    requireConfirmation(event) {

      this.$confirm.require({
        target: event.currentTarget,
        group: 'headless',
        message: 'Are you sure? You cannot undo this.',
        accept: () => {

          if (this.localRule.id) {
            this.deleteRule(this.localRule.id);
          }
        },
        reject: () => {
        }
      });
    },
    resetForm() {
      this.localRule = {
        path_matching: "exact",
        body_matching: "exact",
        method: "ANY",

      };
    },
    submitForm() {
      const ruleToSubmit = Object.assign({}, this.localRule);
      delete ruleToSubmit.parsed;

      fetch(this.config.backendAddress + "/contentrule/upsert", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(ruleToSubmit),
      })
        .then((response) => response.json())
        .then((response) => {
          if (response.status == this.config.backendResultNotOk) {
            this.$toast.error(response.message);
          } else {
            this.$toast.success("Saved rule");
            this.$emit("update-rule");
          }
        });
    },
    deleteRule(id) {
      fetch(this.config.backendAddress + "/contentrule/delete", {
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
            this.$toast.success("Deleted rule");
            this.resetForm();
            this.$emit("delete-rule");
          }
        });
    },
    loadApps(callback) {
      fetch(this.config.backendAddress + "/app/all")
        .then((response) => response.json())
        .then((response) => {
          if (response.status == this.config.backendResultNotOk) {
            this.$toast.error(response.message);
          } else {
            this.appValues = [];
            if (response.data) {
              for (var i = 0; i < response.data.length; i++) {
                const newApp = Object.assign({}, response.data[i]);
                const appValue = newApp.name + ' ' + newApp.version;
                this.appValues.push({ label: appValue, value: newApp.id });
              }
            }
          }
          callback()
        });
    },
  },
  watch: {
    rule() {
      this.localRule = Object.assign({}, this.rule);
    },
    contentid() {
      if (this.contentid > 0) {
        this.localRule.content_id = this.contentid;
      }
    },
    appid() {
      if (this.appid > 0) {
        const that = this;
        this.loadApps(function() {
          that.localRule.app_id = that.appid;
        });
      }
    },
  },
  created() {
    this.loadApps(function() {});
  },
};
</script>

<style scoped>
textarea {
  width: 100%;
  height: 400px;
}
</style>
