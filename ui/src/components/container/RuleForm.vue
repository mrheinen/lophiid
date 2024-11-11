<template>
  <div>
    <input type="hidden" name="id" v-model="localRule.id" />
    <div>
      <FieldSet legend="Settings" :toggleable="false">
        <div class="columns">
          <div class="column">
            <div>
              <label class="label">URI match string</label>
              <InputText
                id="title"
                type="text"
                placeholder=""
                v-model="localRule.uri"
              />
            </div>
          </div>
          <div class="column">
            <div class="field">
              <label class="label">URI matching method</label>
              <FormSelect
                v-model="localRule.uri_matching"
                :options="config.backendMatchingMethods"
                placeholder="Select a
              method"
                checkmark
                :highlightOnSelect="true"
              />
            </div>
          </div>
        </div>

        <div class="columns">
          <div class="column">
            <div>
              <label class="label">Request body match string</label>
              <InputText
                id="title"
                type="text"
                placeholder=""
                v-model="localRule.body"
              />
            </div>
          </div>
          <div class="column">
            <div class="field">
              <label class="label">Body matching method</label>
              <FormSelect
                v-model="localRule.body_matching"
                :options="config.backendMatchingMethods"
                placeholder="Select a
              method"
                checkmark
                :highlightOnSelect="true"
              />
            </div>
          </div>
        </div>

        <div class="columns">
          <div class="column">
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
              <i
                @click="onContentFormOpen()"
                class="pi pi-plus-circle pointer"
              ></i>
              &nbsp;
              <a :href="config.contentLink + '?q=id:' + localRule.content_id">
                <i class="pi pi-external-link pointer"></i>
              </a>
            </div>
          </div>
          <div class="column">
            <div>
              <label class="label">App ID</label>
              <FormSelect
                v-model="localRule.app_id"
                :options="appValues"
                optionLabel="label"
                optionValue="value"
                placeholder="Select app"
                class="w-full md:w-14rem"
              />

              &nbsp;
              <i @click="onAppFormOpen()" class="pi pi-plus-circle pointer"></i>
            </div>
          </div>
        </div>

        <div class="columns">
          <div class="column">
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
          </div>
          <div class="column">
            <div class="field">
              <label class="label">Request purpose</label>
              <FormSelect
                v-model="localRule.request_purpose"
                :options="config.contentRuleRequestPurposes"
                placeholder="Select a
              method"
                checkmark
                :highlightOnSelect="true"
              />
            </div>
          </div>
        </div>

        <div class="columns">
          <div class="column">
            <div>
              <label class="label">HTTP method</label>
              <FormSelect
                v-model="localRule.method"
                :options="config.contentRuleHTTPMethods"
                placeholder="Select HTTP method"
                checkmark
                :highlightOnSelect="true"
              />
            </div>
          </div>
          <div class="column">
            <div>
              <label class="label">UUID</label>
              <InputText
                id="uuid"
                type="text"
                disabled
                placeholder="The UUID of the rule"
                v-model="localRule.ext_uuid"
              />
            </div>
          </div>
        </div>

        <div class="columns">
          <div class="column">
            <div>
              <label class="label">Responder (optional)</label>
              <FormSelect
                v-model="localRule.responder"
                :options="config.ruleResponderTypes"
                placeholder="Responder type"
                checkmark
                :highlightOnSelect="true"
              />
            </div>
          </div>
          <div class="column">
            <div>
              <label class="label">Responder regex</label>
              <InputText
                id="responder_regex"
                type="text"
                placeholder="Responder regex"
                v-model="localRule.responder_regex"
              />
            </div>
          </div>
        </div>

        <div class="columns">
          <div class="column">
            <div>
              <label class="label">Responder decoder</label>
              <FormSelect
                v-model="localRule.responder_decoder"
                :options="config.ruleResponderDecoders"
                placeholder="Responder decoder"
                checkmark
                :highlightOnSelect="true"
              />
            </div>
          </div>
          <div class="column">
            <label class="label">Misc options</label>
            <div>
              <CheckBox
                inputId="alert"
                v-model="localRule.alert"
                :binary="true"
              />
              <label for="alert">Alert</label>
            </div>

            <div>
              <CheckBox
                inputId="enabled"
                v-model="localRule.enabled"
                :binary="true"
              />
              <label for="enabled">Enable</label>
            </div>
          </div>
        </div>
        <br />
        <PrimeButton
          :label="localRule.id > 0 ? 'Submit' : 'Add'"
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
  props: ["rule", "contentid", "appid"],
  emits: [
    "require-auth",
    "update-rule",
    "delete-rule",
    "content-form-open",
    "app-form-open",
  ],
  inject: ["config"],
  data() {
    return {
      localRule: {
        uri_matching: "exact",
        body_matching: "exact",
        method: "ANY",
      },
      appValues: [],
    };
  },
  methods: {
    onContentFormOpen() {
      this.$emit("content-form-open");
    },
    onAppFormOpen() {
      this.$emit("app-form-open");
    },
    requireConfirmation(event) {
      this.$confirm.require({
        target: event.currentTarget,
        group: "headless",
        message: "Are you sure? You cannot undo this.",
        accept: () => {
          if (this.localRule.id) {
            this.deleteRule(this.localRule.id);
          }
        },
        reject: () => {},
      });
    },
    resetForm() {
      this.localRule = {
        uri_matching: "none",
        body_matching: "none",
        method: "ANY",
        request_purpose: "UNKNOWN",
      };
    },
    submitForm() {
      const ruleToSubmit = Object.assign({}, this.localRule);
      delete ruleToSubmit.parsed;

      fetch(this.config.backendAddress + "/contentrule/upsert", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "API-Key": this.$store.getters.apiToken,
        },
        body: JSON.stringify(ruleToSubmit),
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
            this.$toast.success("Saved rule");
            this.$emit("update-rule", ruleToSubmit.id);
          }
        });
    },
    deleteRule(id) {
      fetch(this.config.backendAddress + "/contentrule/delete", {
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
            this.$toast.success("Deleted rule");
            this.resetForm();
            this.$emit("delete-rule");
          }
        });
    },
    loadApps(callback) {
      const url =
        this.config.backendAddress + "/app/segment?q=&limit=1000&offset=0";
      fetch(url, {
        headers: {
          "API-Key": this.$store.getters.apiToken,
        },
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
            this.appValues = [];
            if (response.data) {
              for (var i = 0; i < response.data.length; i++) {
                const newApp = Object.assign({}, response.data[i]);
                const appValue = newApp.name + " " + newApp.version;
                this.appValues.push({ label: appValue, value: newApp.id });
              }
            }
          }
          callback();
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
        this.loadApps(function () {
          that.localRule.app_id = that.appid;
        });
      }
    },
  },
  created() {
    this.loadApps(function () {});
  },
};
</script>

<style scoped>
textarea {
  width: 100%;
  height: 400px;
}

.pointer {
  cursor: pointer;
}
</style>
