<template>
  <PrimeDialog
    v-model:visible="apiTokenDialogVisible"
    modal
    header="Set API token"
    :style="{ width: '25rem' }"
  >
    <div class="flex justify-content-end gap-2">
      <div style="padding-right: 10px">
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

  <div class="grid grid-flow-row auto-rows-auto grow-0">
    <div style="">
      <vue-nav-bar> </vue-nav-bar>
    </div>
    <div style="margin-top: 20px; margin-left: 15px">
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
html {
  font-size: 0.75rem;
}

a:link {
  text-decoration: none;
  color: #2112b7;
}

a:visited {
  text-decoration: none !important;
  color: #2112b7;
}

a:hover {
  text-decoration: underline;
}

a:active {
  text-decoration: underline;
}

.mright {
  margin-right: 10px;
}

.mleft {
  margin-left: 15px;
  margin-right: 30px;
}

th {
  color: #616060 !important;
  text-align: left;
}

td {
  text-align: left;
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

  color: #363636;
  display: block;
  font-size: 1rem;
  font-weight: 700;
}

.linkpointer {
  cursor: pointer !important;
}

.p-datatable-row-selected {
  /* background-color: #f7f6eb !important; */
  color: black !important;
  border-color: black !important;
}
</style>
