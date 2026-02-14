<template>
  <div>
    <FormSelect
    v-model="localValue"
    :options="options"
    optionValue="id"
    optionLabel="name"
    />
  </div>
</template>

<script>
export default {
  props: {
    modelValue: null,
  },
  inject: ["config"],
  emits: ['update:modelValue'],
  data() {
    return {
      options: [],
    }
  },
  computed: {
    // Computed property to handle two-way binding
    localValue: {
      get() {
        return this.modelValue;
      },
      set(newValue) {
        this.$emit('update:modelValue', newValue);
      }
    }
  },
  methods: {
    fetchOptions() {
      fetch(this.config.backendAddress + "/rulegroup/segment?offset=0&limit=1000&q=", {
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
              this.options = response.data;
            }
          }
        });
    },
  },
  mounted() {
    this.fetchOptions();
  },
};
</script>

<style scoped>
</style>
