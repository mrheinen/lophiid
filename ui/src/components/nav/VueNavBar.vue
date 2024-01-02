<template>
  <div class="card" style="margin-left: 10px">
    <MenuBar :model="items">
      <template #start>
        <img src="@/assets/logo.png" width="112" height="28" />
      </template>
      <template #item="{ item, props, hasSubmenu, root }">
        <a v-ripple class="flex align-items-center" v-bind="props.action">
          <span :class="item.icon" />
          <span class="ml-2">{{ item.label }}</span>
          <Badge
            v-if="item.badge"
            :class="{ 'ml-auto': !root, 'ml-2': root }"
            :value="item.badge"
          />
          <span
            v-if="item.shortcut"
            class="ml-auto border-1 surface-border border-round surface-100 text-xs p-1"
            >{{ item.shortcut }}</span
          >
          <i
            v-if="hasSubmenu"
            :class="[
              'pi pi-angle-down text-primary',
              { 'pi-angle-down ml-2': root, 'pi-angle-right ml-auto': !root },
            ]"
          ></i>
        </a>
      </template>

      <template #end>
        <div class="flex align-items-center gap-2">
        </div>
      </template>
    </MenuBar>
  </div>
</template>

<script>
export default {
  inject: ["config"],
  methods: {},
  data() {
    return {
      items: [
        {
          label: "Content",
          icon: "pi pi-book",
          command: () => {
            this.$router.push(this.config.contentLink);
          },
        },
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
          label: "Downloads",
          icon: "pi pi-download",
          command: () => {
            this.$router.push(this.config.downloadsLink);
          },
        },
      ],
    };
  },
};
</script>

<style scoped>
.router-link-active {
  font-weight: bold;
}
</style>
