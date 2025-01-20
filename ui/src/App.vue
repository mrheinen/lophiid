<template>
  <PrimeDialog
    v-model:visible="apiTokenDialogVisible"
    modal
    header="Set API token"
    :style="{ width: '25rem' }"
  >
    <label class="label">Set the API key</label>
    <div class="flex justify-content-end gap-2">
      <div style="padding-right: 10px;">
        <InputText id="apiKey" type="text" v-model="apiKey" />
      </div>
      <div>
        <PrimeButton
          type="button"
          label="Close"
          @click="apiTokenDialogVisible = false"
        ></PrimeButton>
      </div>
    </div>
  </PrimeDialog>

  <div class="columns">
    <div class="column is-full">
      <vue-nav-bar> </vue-nav-bar>
    </div>
  </div>

  <div class="columns">
    <div class="column is-full">
      <!-- use key below to let the page re-render when the API key changes -->
      <router-view
        :key="apiKey + $route.path"
        @require-auth="requireAuth"
      ></router-view>
    </div>
  </div>
</template>

<script>
import VueNavBar from "./components/nav/VueNavBar.vue";
import Config from "./Config.js";
import { readonly } from "vue";

export default {
  components: {
    VueNavBar,
  },
  data() {
    return {
      apiKey: "",
      apiTokenDialogVisible: false,
    };
  },
  methods: {
    requireAuth() {
      this.apiTokenDialogVisible = true;
    },
  },
  provide() {
    return {
      // Provide the config to all components.
      config: readonly(Config),
    };
  },
  watch: {
    apiKey() {
      this.$store.commit("setApiToken", {
        token: this.apiKey,
      });
    },
    apiTokenDialogVisible(newValue) {
      if (newValue) {
        setTimeout(() => {
          const input = document.getElementById("apiKey");
          input.focus();
        }, 1000);
      }
    },
  },
};
</script>

<style>
.mright {
  margin-right: 10px;
}

th {
  color: #616060 !important;
}

td {
  text-align: left;
}

tr {
  font-size: 13px;
}

.myMard {
  background: #fff;
  border: 1px solid #e2e8f0;
  border-radius: 10px;
  margin-bottom: 1rem;
  padding: 2rem;
}

label {
  color: #616060 !important;
  margin-top: 0.5em;
}

.linkpointer {
  cursor: pointer !important;
}
</style>
