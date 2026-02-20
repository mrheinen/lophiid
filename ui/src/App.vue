<template>
  <PrimeDialog
    v-model:visible="apiTokenDialogVisible"
    modal
    header="Authentication Required"
    :style="{ width: '28rem' }"
    :pt="{ header: { class: 'pb-2' } }"
  >
    <p class="app-dialog-hint">
      Enter your API token to continue.
    </p>
    <div class="app-dialog-form">
      <InputText
        id="apiKey"
        v-model="apiKey"
        type="password"
        placeholder="Paste your API token"
        class="app-dialog-input"
        @keyup.enter="apiTokenDialogVisible = false"
      />
      <PrimeButton
        type="button"
        label="Connect"
        icon="pi pi-sign-in"
        @click="apiTokenDialogVisible = false"
      />
    </div>
  </PrimeDialog>

  <div class="app-layout">
    <header class="app-header">
      <vue-nav-bar />
    </header>
    <main class="app-main">
      <!-- use key below to let the page re-render when the API key changes -->
      <router-view
        :key="apiKey + $route.path"
        @require-auth="requireAuth"
      />
    </main>
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
  provide() {
    return {
      // Provide the config to all components.
      config: readonly(Config),
    };
  },
  data() {
    return {
      apiKey: "",
      apiTokenDialogVisible: false,
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
          if (input) input.focus();
        }, 300);
      }
    },
  },
  methods: {
    requireAuth() {
      this.apiTokenDialogVisible = true;
    },
  },
};
</script>

<style>
/* ===== Base Reset & Typography ===== */
*,
*::before,
*::after {
  box-sizing: border-box;
}

html {
  font-size: 13px;
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;
}

body {
  margin: 0;
  font-family: 'Source Sans Pro', 'Roboto', -apple-system, BlinkMacSystemFont,
    'Segoe UI', sans-serif;
  background-color: var(--p-surface-50);
  color: var(--p-text-color);
}

/* ===== App Layout ===== */
.app-layout {
  display: flex;
  flex-direction: column;
  min-height: 100vh;
}

.app-header {
  position: sticky;
  top: 0;
  z-index: 1000;
}

.app-main {
  flex: 1;
  padding: 1.25rem 1.5rem;
  max-width: 100%;
  overflow-x: hidden;
}

/* ===== Auth Dialog ===== */
.app-dialog-hint {
  color: var(--p-text-muted-color);
  margin: 0 0 1rem 0;
  font-size: 0.925rem;
}

.app-dialog-form {
  display: flex;
  gap: 0.5rem;
  align-items: stretch;
}

.app-dialog-input {
  flex: 1;
}

/* ===== Links ===== */
a {
  text-decoration: none;
  color: var(--p-primary-600);
  transition: color 0.15s ease;
}

a:visited {
  color: var(--p-primary-600);
}

a:hover {
  color: var(--p-primary-700);
  text-decoration: underline;
}

/* ===== Table Defaults ===== */
th {
  color: var(--p-text-muted-color) !important;
  text-align: left;
  font-weight: 600;
}

td {
  text-align: left;
}

/* ===== Form Labels ===== */
label {
  color: var(--p-text-muted-color);
  margin-top: 0.5em;
  display: block;
  font-size: 0.875rem;
  font-weight: 600;
  margin-bottom: 0.25rem;
}

/* ===== DataTable Enhancements ===== */
.p-datatable .p-datatable-tbody > tr > td {
  padding: 0.5rem 0.75rem !important;
  font-size: 0.925rem;
}

.p-datatable .p-datatable-thead > tr > th {
  padding: 0.625rem 0.75rem !important;
  font-weight: 600;
  font-size: 0.875rem;
  text-transform: uppercase;
  letter-spacing: 0.025em;
  color: var(--p-text-muted-color);
  background: var(--p-surface-50);
}

.p-datatable-row-selected {
  color: var(--p-text-color) !important;
}

.p-datatable .p-datatable-tbody > tr:hover {
  background: var(--p-surface-50) !important;
}

.p-datatable .p-datatable-tbody > tr.p-datatable-row-selected {
  background: var(--p-primary-50) !important;
  border-left: 3px solid var(--p-primary-500);
}

/* ===== Utility Classes ===== */
.pointer {
  cursor: pointer !important;
}

.linkpointer {
  cursor: pointer !important;
}

/* ===== Pagination Arrows (shared) ===== */
i.pi-style {
  font-size: 1.5rem;
  color: var(--p-primary-500);
  cursor: pointer;
  transition: color 0.15s ease;
  padding: 0.25rem;
}

i.pi-style:hover {
  color: var(--p-primary-700);
}

i.pi-style-disabled {
  font-size: 1.5rem;
  color: var(--p-surface-300);
  padding: 0.25rem;
}

i.pi-style-right {
  float: right;
}

/* ===== Tag Styles ===== */
.mytag {
  font-size: 0.75rem;
  display: inline-block;
  background-color: var(--p-surface-100);
  padding: 0.125rem 0.5rem;
  border-radius: 1rem;
  margin-left: 0.25rem;
  margin-bottom: 0.125rem;
  font-weight: 500;
  transition: opacity 0.15s ease;
}

.mytag:hover {
  opacity: 0.85;
}

/* ===== Filter Cell Pattern (shared for alt-click filtering) ===== */
.filter-cell {
  position: relative;
  display: block;
}

.filter-icon {
  position: absolute;
  right: -10px;
  top: -3px;
  font-size: 0.7rem;
  color: var(--p-primary-500);
}

.filter-icon-exclude {
  color: var(--p-red-400);
}

/* ===== Starred ===== */
.starred {
  color: var(--p-red-500);
}

/* ===== Alert ===== */
.alert {
  color: var(--p-red-500);
}

/* ===== DataTable shrink-to-fit columns ===== */
.col-shrink {
  white-space: nowrap;
  width: 1%;
}

/* ===== List Page Layout ===== */
.list-layout {
  display: grid;
  grid-template-columns: 3fr 2fr;
  gap: 1rem;
}

.list-table-wrap {
  min-width: 0;
}

.list-form-wrap {
  min-width: 0;
}

/* ===== Whois / Raw preformatted blocks ===== */
pre.whois {
  max-height: 400px;
  max-width: 100%;
  overflow: auto;
  background-color: var(--p-surface-100);
  border: 1px solid var(--p-surface-200);
  border-radius: var(--p-border-radius);
  padding: 0.75rem;
  font-size: 0.85rem;
  word-break: normal !important;
  word-wrap: normal !important;
  white-space: pre !important;
}
</style>
