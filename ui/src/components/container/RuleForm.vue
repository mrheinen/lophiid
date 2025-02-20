<template>
  <div>
    <input type="hidden" name="id" v-model="localRule.id" />
    <div>

    <InfoCard mylabel="Settings">
    <template #default>
        <div class="grid grid-cols-2 gap-4">
          <div class="">
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
          <div class="">
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

          <div class="">
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
          <div class="">
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

          <div class="">
            <div>
              <label class="label"
                >Content ID &nbsp;
                <i
                  @click="onContentFormOpen()"
                  class="pi pi-plus-circle pointer"
                ></i>
                &nbsp;
                <a :href="config.contentLink + '?q=id:' + localRule.content_id">
                  <i class="pi pi-external-link pointer"></i>
                </a>
              </label>
              <InputNumber
                v-model="localRule.content_id"
                inputId="minmax"
                :useGrouping="false"
                :min="0"
                :max="65535"
              />
            </div>
          </div>
          <div class="">
            <div>
              <label class="label"
                >App ID &nbsp;<i
                  @click="onAppFormOpen()"
                  class="pi pi-plus-circle pointer"
                ></i>
              </label>
              <FormSelect
                v-model="localRule.app_id"
                :options="appValues"
                optionLabel="label"
                optionValue="value"
                placeholder="Select app"
                class="w-full md:w-14rem"
              />
            </div>
          </div>

          <div class="">
            <div>
              <label class="label">Ports</label>
              <InputText
                placeholder="Comma separated"
                id="ports"
                type="text"
                v-model="localRule.parsed.port_field"
              />
            </div>
          </div>
          <div class="">
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

          <div class="">
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
          <div class="">
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

          <div class="">
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
          <div class="">
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

          <div class="">
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

          <div>
            <label class="label">Misc options</label>
            <table>
              <tr>
                <th>Alert</th>
                <td>
                  <CheckBox
                    inputId="alert"
                    v-model="localRule.alert"
                    :binary="true"
                  />
                </td>
              </tr>
              <tr>
                <th>Enable</th>
                <td>
                  <CheckBox
                    inputId="enabled"
                    v-model="localRule.enabled"
                    :binary="true"
                  />
                </td>
              </tr>
            </table>
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
        body_matching: "none",
        method: "ANY",
        ports: [],
        parsed: {
          port_field: "",
        }
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
        uri_matching: "exact",
        body_matching: "none",
        method: "ANY",
        request_purpose: "UNKNOWN",
        responder: "NONE",
        responder_decoder: "NONE",
        enabled: true,
        ports: [],
        parsed: {
          port_field: "",

        },
      };
    },
    submitForm() {
      const ruleToSubmit = Object.assign({}, this.localRule);

      ruleToSubmit.ports = [];
      if (ruleToSubmit.parsed.port_field != "") {

        for (let port of ruleToSubmit.parsed.port_field.split(",")) {
          var intPort = parseInt(port);

          if (intPort < 0 || intPort > 65535) {
            this.$toast.error("Invalid port: " + port);
          } else {
            ruleToSubmit.ports.push(intPort);
          }
        }
      }

      delete ruleToSubmit.parsed;
      delete ruleToSubmit.app_version;
      delete ruleToSubmit.app_name;

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
            return;
          } else {
            return response.json();
          }
        })
        .then((response) => {
          if (!response) {
            return;
          }
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
      this.localRule.parsed = {};
      if (this.localRule.ports && this.localRule.ports != "") {
        this.localRule.parsed.port_field = this.localRule.ports.join(",");
      }
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

.p-select {
  width: 100%;
}

.pointer {
  cursor: pointer;
}
</style>
