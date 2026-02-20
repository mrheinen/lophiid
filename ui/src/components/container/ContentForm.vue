<template>
  <div>
    <input
      v-model="localContent.id"
      type="hidden"
      name="id"
    >
    <InfoCard mylabel="Required fields">
      <template #default>
        <div>
          <label class="label">Title</label>
          <InputText
            id="title"
            v-model="localContent.name"
            type="text"
            placeholder="Small summary"
          />
        </div>

        <div>
          <label class="label">Description</label>
          <TextArea
            v-model="localContent.description"
            rows="4"
            cols="40"
          />
        </div>

        <div>
          <label class="label">UUID</label>
          <InputText
            id="uuid"
            v-model="localContent.ext_uuid"
            type="text"
            disabled
            placeholder="The UUID of the content"
          />
        </div>

        <div class="mt-3">
          <input
            v-if="!scriptMode"
            type="file"
            @change="handleFileUpload"
          >
          <div v-if="scriptMode">
            <label class="label">Content Script</label>
            <codemirror
              v-model="localContent.script"
              :style="{ height: '400px' }"
              :extensions="extensions"
            />
          </div>
        </div>

        <div class="mt-3">
          <PrimeButton
            severity="secondary"
            :label="scriptMode ? 'Exit Script Mode' : 'Enter Script Mode'"
            :icon="scriptMode ? 'pi pi-times' : 'pi pi-code'"
            @click="scriptMode = !scriptMode"
          />
        </div>
      </template>
    </InfoCard>

    <InfoCard mylabel="Extra options">
      <template #default>
        <div>
          <label class="label">HTTP status code</label>
          <FormSelect
            v-model="localContent.status_code"
            :options="config.statusCodeValues"
            option-label="label"
            option-value="value"
          />
        </div>

        <div>
          <label class="label">Content type</label>
          <div class="flex justify-content-center">
            <AutoComplete
              v-model="localContent.content_type"
              :suggestions="contentTypeItems"
              @complete="contentTypeSearch"
            />
          </div>
        </div>

        <div>
          <label class="label">Web server</label>
          <div class="flex justify-content-center">
            <AutoComplete
              v-model="localContent.server"
              :suggestions="serverItems"
              @complete="serverSearch"
            />
          </div>
        </div>

        <div>
          <label class="label">Custom headers</label>
          <TextArea
            v-model="customHeaders"
            rows="4"
            cols="40"
          />
        </div>

        <div>
        <label class="label">Extra options</label>
        <table>
          <tbody>
            <tr>
              <th>Interpret data</th>
              <td>
                <CheckBox
                  v-model="localContent.has_code"
                  input-id="has_code"
                  :binary="true"
                />
              </td>
            </tr>
          </tbody>
        </table>
        </div>

        <div v-if="!scriptMode">
          <label class="label">Data</label>
          <TextArea
            v-model="localContent.data"
            rows="20"
            cols="70"
          />
        </div>
      </template>
    </InfoCard>
    <div class="flex gap-2 mt-3">
      <PrimeButton
        :label="localContent.id > 0 ? 'Submit' : 'Add'"
        icon="pi pi-check"
        @click.prevent="submitForm()"
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
  </div>
  <ConfirmPopup />
</template>

<script>
import { javascript } from "../../../node_modules/@codemirror/lang-javascript";
import {
  keymap,
  highlightActiveLine,
  highlightSpecialChars,
  lineNumbers,
  highlightActiveLineGutter,
} from "../../../node_modules/@codemirror/view";

import {
  defaultKeymap,
  history,
  historyKeymap,
  indentWithTab,
} from "../../../node_modules/@codemirror/commands";

import {
  search,
  searchKeymap,
  highlightSelectionMatches,
} from "../../../node_modules/@codemirror/search";

import {
  autocompletion,
  completionKeymap,
  closeBrackets,
  closeBracketsKeymap,
} from "../../../node_modules/@codemirror/autocomplete";
import {
  indentOnInput,
  bracketMatching,
  foldGutter,
  foldKeymap,
} from "../../../node_modules/@codemirror/language";

import { lintKeymap } from "../../../node_modules/@codemirror/lint";
import { solarizedLight } from "../../../node_modules/thememirror/dist";

export default {
  inject: ["config"],
  props: {
    "content": {
      type: Object,
      required: true
    },
  },
  emits: ["update-content", "deleted-content", "require-auth"],
  data() {
    return {
      localContent: {
        server: "Apache",
        status_code: "200",
        headers: [],
      },
      contentTypeItems: [],
      serverItems: [],
      customHeaders: "",
      selectedFile: null,
      showContentData: false,
      scriptMode: false,
      extensions: [
        solarizedLight,
        indentOnInput(),
        history(),
        bracketMatching(),
        javascript(),
        foldGutter(),
        closeBrackets(),
        autocompletion(),
        highlightActiveLine(),
        highlightSpecialChars(),
        lineNumbers(),
        highlightActiveLineGutter(),
        highlightSelectionMatches(),
        search({ top: true }),
        keymap.of([
          ...closeBracketsKeymap,
          ...defaultKeymap,
          ...searchKeymap,
          ...historyKeymap,
          ...foldKeymap,
          ...completionKeymap,
          ...lintKeymap,
          indentWithTab,
        ]),
      ],
    };
  },
  watch: {
    content() {
      this.localContent = Object.assign({}, this.content);
      if (this.localContent.script && this.localContent.script.length > 0) {
        this.scriptMode = true;
      }

      var customHeaderTmp = "";
      if (this.localContent.headers) {
        var prefix = "";
        this.localContent.headers.forEach((header) => {
          customHeaderTmp += prefix + header;
          prefix = "\n";
        });
        this.customHeaders = customHeaderTmp;
      }

    },
  },
  methods: {
    requireConfirmation(event) {
      if (!this.localContent.id) {
        return;
      }
      this.$confirm.require({
        target: event.currentTarget,
        message: "Are you sure? You cannot undo this.",
        accept: () => {
          if (this.localContent.id) {
            this.deleteContent(this.localContent.id);
          }
        },
        reject: () => {},
      });
    },

    handleFileUpload(event) {
      const reader = new FileReader();
      reader.addEventListener("load", (event) => {
        this.localContent.data = event.target.result;
        console.log(event.target.result);
      });

      this.selectedFile = event.target.files[0];
      reader.readAsBinaryString(this.selectedFile);

      if (
        !this.localContent.content_type ||
        this.localContent.content_type == ""
      ) {
        this.localContent.content_type = this.selectedFile.type;
      }
      console.log(this.selectedFile);
    },
    contentTypeSearch() {
      const that = this;
      this.contentTypeItems = this.config.contentTypeValues.filter(function (
        str
      ) {
        return str.startsWith(that.localContent.content_type);
      });
    },
    serverSearch() {
      const that = this;
      this.serverItems = this.config.serverValues.filter(function (str) {
        return str.startsWith(that.localContent.server);
      });
    },

    resetForm() {
      this.localContent = {};
      this.customHeaders = "";
    },
    submitForm() {
      if (
        this.localContent.script &&
        this.localContent.script.length > 0 &&
        this.localContent.data &&
        this.localContent.data.length > 0
      ) {
        this.$toast.error("Either specify a script or content data. Not both");
        return;
      }

      this.localContent.headers = []
      if (this.customHeaders != "") {
        var headers = this.customHeaders.split("\n");
        if (!headers || headers.length == 0) {
          headers.push(this.customHeaders);
        }
        var returnNow = false;
        headers.forEach((header) => {
          var checkParts = header.split(": ");
          if (checkParts.length < 2) {
            this.$toast.error("This header seems wrong: '" + header + "'");
            returnNow = true;
          }
          this.localContent.headers.push(header);
        });
        if (returnNow == true) {
          return;
        }
      }
      const contentToSubmit = Object.assign({}, this.localContent);
      // Remove the added fields.
      delete contentToSubmit.parsed;
      if (contentToSubmit.data) {
        contentToSubmit.data = btoa(contentToSubmit.data);
      }

      fetch(this.config.backendAddress + "/content/upsert", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "API-Key": this.$store.getters.apiToken,
        },
        body: JSON.stringify(contentToSubmit),
      })
        .then((response) => {
          if (response.status == 403) {
            this.$emit('require-auth');
          } else {
            return response.json()
          }
        })
        .then((response) => {
          if (response.status == this.config.backendResultNotOk) {
            this.$toast.error(response.message);
          } else {
            if (response.data && response.data.length > 0) {
              this.$emit("update-content", response.data[0].id);
            } else {
              if (this.localContent.id == 0) {
                // Or should this be a console.log?
                this.$toast.error("Did an update on ID 0 ?");
              } else {
                this.$emit("update-content", this.localContent.id);
              }
            }
            this.$toast.success("Saved entry");
          }
        });
    },

    deleteContent(id) {
      fetch(this.config.backendAddress + "/content/delete", {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          "API-Key": this.$store.getters.apiToken,
        },
        body: "id=" + id,
      })
        .then((response) => {
          if (response.status == 403) {
            this.$emit('require-auth');
          } else {
            return response.json()
          }
        })
        .then((response) => {
          if (response.status == this.config.backendResultNotOk) {
            this.$toast.error(response.message);
          } else {
            this.$toast.success("Deleted entry");
            this.resetForm();
            this.$emit("deleted-content");
          }
        });
    },
  },
};
</script>

<style scoped>

textarea {
  width: 100%;
}

.p-inputwrapper {
  width: 100%;
}

.button-group {
  padding: 1.25em;
}

</style>
