<template>
  <div
    class="card"
    style=""
  >
    <MenuBar
      :model="items"
      :pt="{ root: 'shadow-md shadow-stone-500/50' }"
    >
      <template #start>
        <img
          src="@/assets/logo.png"
          width="112"
          height="28"
        >
      </template>
      <template #item="{ item, props, hasSubmenu, root }">
        <a
          class="flex align-items-center"
          v-bind="props.action"
        >
          <span :class="item.icon" />
          <span class="ml-2">{{ item.label }}</span>
          <PrimeBadge
            v-if="item.badge"
            :class="{ 'ml-auto': !root, 'ml-2': root }"
            :value="item.badge"
          />
          <span
            v-if="item.shortcut"
            class="ml-auto border-1 surface-border border-round surface-100 text-xs p-1"
          >{{ item.shortcut }}</span>
          <i
            v-if="hasSubmenu"
            :class="[
              'pi pi-angle-down text-primary',
              { 'pi-angle-down ml-2': root, 'pi-angle-right ml-auto': !root },
            ]"
          />
        </a>
      </template>

      <template #end>
        <div class="flex align-items-center gap-2" />
      </template>
    </MenuBar>
  </div>
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
          icon: "ico pi pi-database",
          command: () => {
            this.$router.push(this.config.requestsLink);
          },
        },
        {
          label: "Honeypots",
          icon: "ico pi pi-eye",
          command: () => {
            this.$router.push(this.config.honeypotsLink);
          },
        },
        {
          label: "Events",
          icon: "ico pi pi-server",
          command: () => {
            this.$router.push(this.config.eventLink);
          },
        },

        {
          label: "Simulate",
          icon: "ico pi pi-link",
          items: [
            {
              label: "Content",
              icon: "ico pi pi-book",
              command: () => {
                this.$router.push(this.config.contentLink);
              },
            },

            {
              label: "Rules",
              icon: "ico pi pi-directions",
              command: () => {
                this.$router.push(this.config.rulesLink);
              },
            },
            {
              label: "Apps",
              icon: "ico pi pi-box",
              command: () => {
                this.$router.push(this.config.appsLink);
              },
            },
          ],
        },

        {
          label: "Malware",
          icon: "ico pi pi-exclamation-triangle",
          items: [
            {
              label: "Yara",
              icon: "ico pi pi-list",
              command: () => {
                this.$router.push(this.config.yaraLink);
              },
            },
            {
              label: "Downloads",
              icon: "ico pi pi-download",
              command: () => {
                this.$router.push(this.config.downloadsLink);
              },
            },
          ],
        },

        {
          label: "Queries",
          icon: "ico pi pi-search",
          items: [
            {
              label: "Manage queries",
              icon: "ico pi pi-search",
              command: () => {
                this.$router.push(this.config.storedqueryLink);
              },
            },
            {
              label: "Manage labels",
              icon: "ico pi pi-tag",
              command: () => {
                this.$router.push(this.config.tagsLink);
              },
            },
          ],
        },

        {
          label: "Stats",
          icon: "ico pi pi-chart-bar",
          command: () => {
            this.$router.push(this.config.statsLink);
          },
        },
      ],
    };
  },
  methods: {},
};
</script>

<style scoped>
.router-link-active {
  font-weight: bold;
}

.ml-2 {
  font-size: 21px;
}

.ico {
  font-size: 18px;
}
</style>
