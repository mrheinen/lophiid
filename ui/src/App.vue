<template>
  <div class="columns">
    <div class="column is-full">
      <nav-bar> </nav-bar>
    </div>
  </div>

  <div class="columns">
    <div class="column is-full">
      <router-view></router-view>
    </div>
  </div>
</template>

<script>
import NavBar from "./components/nav/NavBar.vue";
import Config from "./Config.js";
import { readonly } from "vue";

export default {
  components: {
    NavBar,
  },
  provide() {
    return {
      // Provide the config to all components.
      config: readonly(Config),
    };
  },
};
</script>
