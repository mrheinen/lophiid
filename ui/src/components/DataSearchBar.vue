<template>
      <span style="width: 100%">
      <form @submit.prevent="performNewSearch()">
          <IconField iconPosition="left">
            <InputIcon
              class="pi pi-info-circle search-info-icon pointer"
              @click="showPopover"
            >
            </InputIcon>
            <InputText v-model="localQuery" placeholder="Search"/>
          </IconField>
          <SearchPopover
            ref="spop"
            :options="options"
          >
          </SearchPopover>
      </form>
      </span>
</template>

<script>
import SearchPopover from './dialog/SearchPopover.vue';
export default {
  components: {
    SearchPopover,
  },
  props: ["options", "query"],
  emits: ["search"],
  data() {
    return {
      localQuery: null,
    }
  },
  methods: {
    setQuery(query) {
      this.localQuery = query;
      this.$emit('search', this.localQuery);
    },
    showPopover(event) {
      this.$refs.spop.show(event);
    },
    performNewSearch() {
      this.$emit('search', this.localQuery);
    },
  },
  created() {
    if (this.$route.query.q) {
      this.localQuery = this.$route.query.q;
    }
  },
}
</script>


<style scoped>

.p-inputtext {
  width: 100%;
}

span.search-info-icon {
  color: black;
}

span.search-info-icon:hover {
  color: black;
  font-weight: bold !important;
}

</style>
