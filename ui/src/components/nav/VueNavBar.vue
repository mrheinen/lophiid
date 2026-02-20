<template>
  <MenuBar
    :model="items"
    :pt="{
      root: { class: 'navbar-root' },
      item: { class: 'navbar-item' },
    }"
  >
    <template #start>
      <div class="navbar-brand">
        <img
          src="@/assets/logo.png"
          width="112"
          height="28"
          class="navbar-logo"
        >
      </div>
    </template>
    <template #item="{ item, props, hasSubmenu, root }">
      <a
        class="navbar-link"
        v-bind="props.action"
      >
        <span :class="item.icon" />
        <span class="navbar-label">{{ item.label }}</span>
        <PrimeBadge
          v-if="item.badge"
          :class="{ 'ml-auto': !root, 'ml-2': root }"
          :value="item.badge"
          severity="warn"
        />
        <i
          v-if="hasSubmenu"
          :class="[
            'pi pi-angle-down submenu-icon',
            { 'pi-angle-down': root, 'pi-angle-right ml-auto': !root },
          ]"
        />
      </a>
    </template>

    <template #end>
      <div class="navbar-end">
        <a
          href="https://github.com/mrheinen/lophiid"
          target="_blank"
          title="GitHub"
          class="navbar-github"
        >
          <i class="pi pi-github" />
        </a>
      </div>
    </template>
  </MenuBar>
</template>

<script>
export default {
  inject: ["config"],
  data() {
    return {
      items: [
        {
          separator: true,
        },
        {
          label: "Requests",
          icon: "pi pi-database",
          command: () => {
            this.$router.push(this.config.requestsLink);
          },
        },
        {
          label: "Honeypots",
          icon: "pi pi-eye",
          command: () => {
            this.$router.push(this.config.honeypotsLink);
          },
        },
        {
          label: "Events",
          icon: "pi pi-server",
          command: () => {
            this.$router.push(this.config.eventLink);
          },
        },
        {
          label: "Simulate",
          icon: "pi pi-link",
          items: [
            {
              label: "Content",
              icon: "pi pi-book",
              command: () => {
                this.$router.push(this.config.contentLink);
              },
            },
            {
              label: "Rules",
              icon: "pi pi-directions",
              command: () => {
                this.$router.push(this.config.rulesLink);
              },
            },
            {
              label: "Apps",
              icon: "pi pi-box",
              command: () => {
                this.$router.push(this.config.appsLink);
              },
            },
            {
              label: "Rule Groups",
              icon: "pi pi-objects-column",
              command: () => {
                this.$router.push(this.config.ruleGroupsLink);
              },
            },
          ],
        },
        {
          label: "Malware",
          icon: "pi pi-exclamation-triangle",
          items: [
            {
              label: "Yara",
              icon: "pi pi-list",
              command: () => {
                this.$router.push(this.config.yaraLink);
              },
            },
            {
              label: "Downloads",
              icon: "pi pi-download",
              command: () => {
                this.$router.push(this.config.downloadsLink);
              },
            },
          ],
        },
        {
          label: "Queries",
          icon: "pi pi-search",
          items: [
            {
              label: "Manage queries",
              icon: "pi pi-search",
              command: () => {
                this.$router.push(this.config.storedqueryLink);
              },
            },
            {
              label: "Manage labels",
              icon: "pi pi-tag",
              command: () => {
                this.$router.push(this.config.tagsLink);
              },
            },
          ],
        },
        {
          label: "Stats",
          icon: "pi pi-chart-bar",
          command: () => {
            this.$router.push(this.config.statsLink);
          },
        },
      ],
    };
  },
};
</script>

<style scoped>
.navbar-root {
  border-radius: 0 !important;
  border-left: none !important;
  border-right: none !important;
  border-top: none !important;
  background: var(--p-surface-0) !important;
  box-shadow: 0 1px 3px 0 rgba(0, 0, 0, 0.07),
              0 1px 2px -1px rgba(0, 0, 0, 0.05) !important;
  padding: 0 1rem !important;
}

.navbar-brand {
  display: flex;
  align-items: center;
  margin-right: 1.5rem;
}

.navbar-logo {
  display: block;
}

.navbar-link {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  text-decoration: none !important;
  color: var(--p-text-color) !important;
  font-size: 1.6rem;
  font-weight: 500;
  padding: 0.625rem 0.75rem;
  border-radius: var(--p-border-radius);
  transition: background-color 0.15s ease, color 0.15s ease;
}

.navbar-link:hover {
  background-color: var(--p-surface-100);
  text-decoration: none !important;
}

.navbar-label {
  white-space: nowrap;
}

.submenu-icon {
  font-size: 1.3rem;
  margin-left: 0.25rem;
  color: var(--p-text-muted-color);
}

.navbar-end {
  display: flex;
  align-items: center;
  gap: 0.5rem;
}

.navbar-github {
  display: flex;
  align-items: center;
  justify-content: center;
  width: 2rem;
  height: 2rem;
  border-radius: 50%;
  color: var(--p-text-muted-color) !important;
  transition: background-color 0.15s ease, color 0.15s ease;
  font-size: 1.9rem;
}

.navbar-github:hover {
  background-color: var(--p-surface-100);
  color: var(--p-text-color) !important;
  text-decoration: none !important;
}
</style>
