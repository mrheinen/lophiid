<template>
      <span style="width: 100%">
      <form @submit.prevent="performNewSearch()">
          <IconField iconPosition="left">
            <InputIcon
              ref="icon"
              :class="iconClass"
              @click="showPopover"
            >
            </InputIcon>
            <InputText v-model="localQuery" placeholder="Search"/>
          </IconField>
          <SearchPopover
            ref="spop"
            :options="options"
            :modelname="modelname"
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
  props: ["options", "query", "modelname", "isloading"],
  emits: ["search"],
  data() {
    return {
      localQuery: null,
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
      this.$emit('search', this.localQuery);
    },
  },
  created() {
    if (this.$route.query.q) {
      this.localQuery = this.$route.query.q;
    }
  },
  computed: {
    iconClass() {
      return  "pi pi-info-circle search-info-icon pointer" + (this.isloading ? " pi-spin bold" : "")
    },
  }
}
</script>


<style scoped>

.p-inputtext {
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
