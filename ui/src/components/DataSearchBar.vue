<template>
  <div class="search-bar">
    <form
      class="search-bar-form"
      @submit.prevent="performNewSearch()"
    >
      <div class="search-bar-input-wrap">
        <IconField icon-position="left">
          <InputIcon
            ref="icon"
            :class="iconClass"
            @click="showPopover"
          />
          <InputText
            v-model="localQuery"
            placeholder="Search (press Enter to submit)"
            class="search-input"
          />
        </IconField>
        <SearchPopover
          ref="spop"
          :options="options"
          :modelname="modelname"
        />
      </div>
      <FormSelect
        v-if="showage"
        ref="ageSelector"
        v-model="selectedAge"
        :options="ageOptions"
        option-label="name"
        option-value="value"
        placeholder="Time range"
        class="search-age-select"
      />
      <PrimeButton
        type="submit"
        icon="pi pi-search"
        severity="secondary"
        v-tooltip.bottom="'Search'"
        class="search-btn"
      />
    </form>
    <ProgressBar
      v-if="isloading"
      mode="indeterminate"
      class="search-progress"
    />
  </div>
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
      required: false,
    },
    query: {
      type: String,
      required: false,
    },
    modelname: {
      type: String,
      required: true,
    },
    isloading: {
      type: Boolean,
      required: true,
    },
    showage: {
      type: String,
      required: true,
    },
    defaultage: {
      type: [Number, String],
      required: false,
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
        (this.isloading ? " pi-spin" : "")
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
.search-bar {
  width: 100%;
}

.search-bar-form {
  display: flex;
  gap: 0.5rem;
  align-items: stretch;
  flex-wrap: wrap;
}

@media (max-width: 640px) {
  .search-age-select {
    width: 100%;
  }
}

.search-bar-input-wrap {
  flex: 1;
  min-width: 0;
}

.search-bar-input-wrap .p-iconfield {
  width: 100%;
}

.search-input {
  width: 100% !important;
}

.search-age-select {
  width: 10rem;
  flex-shrink: 0;
}

.search-btn {
  flex-shrink: 0;
}

.search-progress {
  height: 3px !important;
  margin-top: 2px;
}

span.search-info-icon {
  color: var(--p-text-muted-color);
  cursor: pointer;
}

span.search-info-icon:hover {
  color: var(--p-text-color);
}
</style>
