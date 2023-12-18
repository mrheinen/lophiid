<template>
  <div class="columns">
    <div class="column is-full">
      <vue-nav-bar> </vue-nav-bar>
    </div>
  </div>

  <div class="columns">
    <div class="column is-full">
      <router-view></router-view>
    </div>
  </div>
</template>

<script>
//import NavBar from "./components/nav/NavBar.vue";
import VueNavBar from "./components/nav/VueNavBar.vue";
import Config from "./Config.js";
import { readonly } from "vue";

export default {
  components: {
    VueNavBar,
  },
  provide() {
    return {
      // Provide the config to all components.
      config: readonly(Config),
    };
  },
};
</script>


<style>
.mright {
 margin-right: 10px;
};


</style>
