<template>
  <div>
    <input type="hidden" name="id" v-model="localYara.id" />
    <div>

    <InfoCard mylabel="Information">
    <template #default>
        <div>
          <label class="label">Yara Result</label>
          <YaraCard :data="localYaraArray"> </YaraCard>
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
  props: ["yara"],
  emits: [],
  inject: ["config"],
  data() {
    return {
      localYara: {},
      localYaraArray: [],
      baseYara: {},
    };
  },
  methods: {},
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
};
</script>

<style scoped></style>
