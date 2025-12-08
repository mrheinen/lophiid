<template>
  <span style="width: 100%">
    <form
      style="display: flex"
      @submit.prevent="performNewSearch()"
    >
      <IconField icon-position="left">
        <InputIcon
          ref="icon"
          :class="iconClass"
          @click="showPopover"
        />
        <InputText
          v-model="localQuery"
          placeholder="Search"
        />
      </IconField>
      <SearchPopover
        ref="spop"
        :options="options"
        :modelname="modelname"
      />
      <FormSelect
        v-if="showage"
        ref="ageSelector"
        v-model="selectedAge"
        :options="ageOptions"
        option-label="name"
        option-value="value"
        placeholder="Months back"
      />
    </form>
  </span>
</template>

<script>
import SearchPopover from "./dialog/SearchPopover.vue";
export default {
  components: {
    SearchPopover,
  },
  props: {
    options: {
      type: Object,
      required: true,
    },
    query: {
      type: Object,
      required: true,
    },
    modelname: {
      type: Object,
      required: true,
    },
    isloading: {
      type: Object,
      required: true,
    },
    showage: {
      type: Object,
      required: true,
    },
    defaultage: {
      type: Object,
      required: true,
    },
  },
  emits: ["search"],
  data() {
    return {
      localQuery: null,
      selectedAge: 0,
      ageOptions: [
        { name: "1 month", value: 1 },
        { name: "2 months", value: 2 },
        { name: "3 months", value: 3 },
        { name: "6 months", value: 6 },
        { name: "12 months", value: 12 },
        { name: "18 months", value: 18 },
        { name: "24 months", value: 24 },
        { name: "36 months", value: 36 },
      ],
    };
  },
  computed: {
    iconClass() {
      return (
        "pi pi-info-circle search-info-icon pointer" +
        (this.isloading ? " pi-spin bold" : "")
      );
    },
  },
  created() {
    if (this.$route.query.q) {
      this.localQuery = this.$route.query.q;
    }

    if (this.showage) {
      this.selectedAge = parseInt(this.defaultage, 10);
    }
  },
  methods: {
    setQuery(query) {
      this.localQuery = query;
    },
    showPopover(event) {
      this.$refs.spop.show(event);
    },
    performNewSearch() {
      this.$emit("search", this.localQuery, this.selectedAge);
    },
  },
};
</script>

<style scoped>
.p-inputtext {
  width: 100%;
}

.p-iconfield {
  width: 100%;
}

.bold {
  font-weight: bold !important;
}
span.search-info-icon {
  color: black;
}

span.search-info-icon:hover {
  color: black;
  font-weight: bold !important;
}
</style>
