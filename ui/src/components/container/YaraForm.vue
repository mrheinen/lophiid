<template>
  <div>
    <input
      v-model="localYara.id"
      type="hidden"
      name="id"
    >
    <div>
      <InfoCard mylabel="Information">
        <template #default>
          <div>
            <label class="label">Yara Result</label>
            <YaraCard :data="localYaraArray" />
          </div>
        </template>
      </InfoCard>
    </div>
  </div>
</template>

<script>
import YaraCard from "../cards/YaraCard.vue";

export default {
  components: {
    YaraCard,
  },
  inject: ["config"],
  props: {
    "yara": {
      type: Object,
      required: true
    }
  },
  emits: [],
  data() {
    return {
      localYara: {},
      localYaraArray: [],
      baseYara: {},
    };
  },
  watch: {
    yara() {
      this.localYara = Object.assign({}, this.yara);
      this.localYara.parsed = {};
      this.localYaraArray = [this.localYara];
    },
  },
  created() {
    //this.localYara = Object.assign({}, this.baseYara);
  },
  methods: {},
};
</script>

<style scoped></style>
