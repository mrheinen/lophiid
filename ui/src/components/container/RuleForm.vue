<template>
  <div>
    <input
      v-model="localRule.id"
      type="hidden"
      name="id"
    >
    <div>
      <InfoCard mylabel="Settings">
        <template #default>
          <div class="grid grid-cols-2 gap-4">
            <div class="">
              <div>
                <label class="label">URI match string</label>
                <InputText
                  id="title"
                  v-model="localRule.uri"
                  type="text"
                  placeholder=""
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
                  :highlight-on-select="true"
                />
              </div>
            </div>

            <div class="">
              <div>
                <label class="label">Request body match string</label>
                <InputText
                  id="title"
                  v-model="localRule.body"
                  type="text"
                  placeholder=""
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
                  :highlight-on-select="true"
                />
              </div>
            </div>

            <div class="">
              <div>
                <label class="label">Content ID &nbsp;
                  <i
                    class="pi pi-plus-circle pointer"
                    @click="onContentFormOpen()"
                  />
                &nbsp;
                  <a :href="config.contentLink + '?q=id:' + localRule.content_id">
                    <i class="pi pi-external-link pointer" />
                  </a>
                </label>
                <InputNumber
                  v-model="localRule.content_id"
                  input-id="minmax"
                  :use-grouping="false"
                  :min="0"
                  :max="65535"
                />
              </div>
            </div>
            <div class="">
              <div>
                <label class="label">App ID &nbsp;<i
                  class="pi pi-plus-circle pointer"
                  @click="onAppFormOpen()"
                />
                </label>
                <FormSelect
                  v-model="localRule.app_id"
                  :options="appValues"
                  option-label="label"
                  option-value="value"
                  placeholder="Select app"
                  class="w-full md:w-14rem"
                />
              </div>
            </div>

            <div class="">
              <div>
                <label class="label">Ports</label>
                <InputText
                  id="ports"
                  v-model="localRule.parsed.port_field"
                  placeholder="Comma separated"
                  type="text"
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
                  :highlight-on-select="true"
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
                  :highlight-on-select="true"
                />
              </div>
            </div>
            <div class="">
              <div>
                <label class="label">UUID</label>
                <InputText
                  id="uuid"
                  v-model="localRule.ext_uuid"
                  type="text"
                  disabled
                  placeholder="The UUID of the rule"
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
                  :highlight-on-select="true"
                />
              </div>
            </div>
            <div class="">
              <div>
                <label class="label">Responder regex</label>
                <InputText
                  id="responder_regex"
                  v-model="localRule.responder_regex"
                  type="text"
                  placeholder="Responder regex"
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
                  :highlight-on-select="true"
                />
              </div>
            </div>
            <div class="">
              <div>
                <label class="label">Tags to apply</label>
                <MultiSelect
                  v-model="localRule.parsed.tags_to_apply"
                  placeholder="Select labels"
                  option-label="name"
                  :options="tags"
                />
              </div>
            </div>


            <div>
              <label class="label">Misc options</label>
              <table>
                <tbody>
                  <tr>
                    <th>Alert</th>
                    <td>
                      <CheckBox
                        v-model="localRule.alert"
                        input-id="alert"
                        :binary="true"
                      />
                    </td>
                  </tr>
                  <tr>
                    <th>Enable</th>
                    <td>
                      <CheckBox
                        v-model="localRule.enabled"
                        input-id="enabled"
                        :binary="true"
                      />
                    </td>
                  </tr>
                  <tr>
                    <th>Block</th>
                    <td>
                      <CheckBox
                        v-model="localRule.block"
                        input-id="block"
                        :binary="true"
                      />
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>
          <br>
          <PrimeButton
            :label="localRule.id > 0 ? 'Submit' : 'Add'"
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
    "rule": {
      type: Object,
      required: true
    },
    "contentid": {
      type: Object,
      required: true
    },
    "appid": {
      type: Object,
      required: true
    }
  },
  emits: [
    "require-auth",
    "update-rule",
    "delete-rule",
    "content-form-open",
    "app-form-open",
  ],
  data() {
    return {
      tags: [],
      tagPerIdMap: new Map(),
      localRule: {
        uri_matching: "exact",
        body_matching: "none",
        method: "ANY",
        ports: [],
        parsed: {
          port_field: "",
          tags_to_apply: [],
        }
      },
      appValues: [],
    };
  },
  watch: {
    rule() {
      this.localRule = Object.assign({}, this.rule);
      this.localRule.parsed = {};
      if (this.localRule.ports && this.localRule.ports != "") {
        this.localRule.parsed.port_field = this.localRule.ports.join(",");
      }

      this.localRule.parsed.tags_to_apply = []

      if (this.localRule.tags_to_apply) {
        this.localRule.tags_to_apply.forEach((qtag) => {
          this.localRule.parsed.tags_to_apply.push(this.tagPerIdMap.get(qtag.tag_id));
        })
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
    this.getAllTags();
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
        block: false,
        ports: [],
        parsed: {
          port_field: "",

        },
      };
    },
    submitForm() {
      const ruleToSubmit = Object.assign({}, this.localRule);

      ruleToSubmit.tags_to_apply = [];
      ruleToSubmit.parsed.tags_to_apply.forEach((tag) => {
        ruleToSubmit.tags_to_apply.push({
          tag_id: tag.id,
        });
      })

      // Remove the added fields.
      ruleToSubmit.ports = [];
      if (ruleToSubmit.parsed.port_field && ruleToSubmit.parsed.port_field != "") {

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
    getAllTags() {
      fetch(this.config.backendAddress + "/tag/segment?offset=0&limit=1000&q=", {
        method: "GET",
        headers: {
          "Content-Type": "application/json",
          "API-Key": this.$store.getters.apiToken,
        },
      })
        .then((response) => {
          if (response.status == 403) {
            this.$emit("require-auth");
            return null;
          } else {
            return response.json();
          }
        })
        .then((response) => {
          if (!response){
            return;
          }
          if (response.status == this.config.backendResultNotOk) {
            this.$toast.error(response.message);
          } else {
            if (response.data) {
              this.tags = response.data;
              response.data.forEach((tag) => {
                this.tagPerIdMap.set(tag.id, tag);
              })
            }
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
};
</script>

<style scoped>
textarea {
  width: 100%;
  height: 400px;
}

.p-multiselect {
  width: 100%;
}

.p-select {
  width: 100%;
}

.pointer {
  cursor: pointer;
}
</style>
