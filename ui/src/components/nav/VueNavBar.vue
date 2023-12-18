<template>
      <div class="card" style="margin-left: 10px">
        <MenuBar :model="items" />
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
                    label: 'Content',
                    icon: 'pi pi-book',
                    command: () => {
                      this.$router.push(this.config.contentLink);
                    }
                },
                {
                    separator: true
                },

                {
                    label: 'Requests',
                    icon: 'pi pi-database',
                    command: () => {
                      this.$router.push(this.config.requestsLink);
                    }
                },
                {
                    label: 'Rules',
                    icon: 'pi pi-directions',
                    command: () => {
                      this.$router.push(this.config.rulesLink);
                    }
                },

                {
                    label: 'Apps',
                    icon: 'pi pi-box',
                    command: () => {
                      this.$router.push(this.config.appsLink);
                    }
                },
            ]
        };
    }
};
</script>

<style scoped>
.router-link-active {
  font-weight: bold;
}
</style>
