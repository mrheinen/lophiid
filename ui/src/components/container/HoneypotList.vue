<template>
  <div class="columns">
    <div class="column is-three-fifths" style="margin-left: 15px">
      <DataSearchBar ref="searchBar" :isloading="isLoading" @search="performNewSearch" modelname="honeypot"></DataSearchBar>

      <table class="table is-hoverable" v-if="honeypots.length > 0">
        <thead>
          <th>ID</th>
          <th>IP</th>
          <th>Version</th>
          <th>First seen</th>
          <th>Last checkin</th>
          <th>Default content</th>
          <th># 24 hours</th>
        </thead>
        <tbody>
          <tr
            v-for="honeypot in honeypots"
            @click="setSelected(honeypot.id)"
            :key="honeypot.id"
            :class="isSelectedId == honeypot.id ? 'is-selected' : ''"
          >
            <td>{{ honeypot.id }}</td>
            <td>
              <a :href="'/requests?q=honeypot_ip:' + honeypot.ip">{{
                honeypot.ip
              }}</a>
            </td>
            <td>{{ honeypot.version }}</td>
            <td>{{ honeypot.parsed.created_at }}</td>
            <td>{{ honeypot.parsed.last_checkin }}</td>
            <td>{{ honeypot.default_content_id }}</td>
            <td>{{ honeypot.request_count_last_day }}</td>
          </tr>
        </tbody>
      </table>

      <i
        v-if="offset > 0"
        @click="loadPrev()"
        class="pi pi-arrow-left pi-style"
      ></i>
      <i
        v-if="honeypots.length == limit"
        @click="loadNext()"
        class="pi pi-arrow-right pi-style pi-style-right"
      ></i>
    </div>
    <div
      class="column mright"
      @focusin="keyboardDisabled = true"
      @focusout="keyboardDisabled = false"
    >
      <honey-form
        @update-honeypot="onUpdateHoneypot"
        @delete-honeypot="onDeleteHoneypot"
        @require-auth="$emit('require-auth')"
        :honeypot="selectedHoneypot"
      ></honey-form>
    </div>
  </div>
</template>

<script>
import { dateToString } from "../../helpers.js";
import HoneyForm from "./HoneypotForm.vue";
import DataSearchBar from "../DataSearchBar.vue";
export default {
  components: {
    HoneyForm,
    DataSearchBar,
  },
  emits: ["require-auth"],
  inject: ["config"],
  data() {
    return {
      honeypots: [],
      selected: null,
      isSelectedId: 0,
      query: null,
      limit: 24,
      offset: 0,
      selectedHoneypot: null,
      keyboardDisabled: false,
      isLoading: false,
      base: {
        id: 0,
        ip: "",
        parsed: {
          last_checkin: "",
        },
      },
    };
  },
  methods: {
    onUpdateHoneypot(id) {
      console.log("Updated ID " + id);
      const that = this;
      this.loadHoneypots(true, function () {
        that.setSelected(id);
      });
    },
    onDeleteHoneypot() {
      this.loadHoneypots(true, function () {});
    },
    performNewSearch(query) {
      this.query = query;
      this.offset = 0;
      this.loadHoneypots(true, function () {});
    },
    setSelected(id) {
      var selected = null;
      for (var i = 0; i < this.honeypots.length; i++) {
        if (this.honeypots[i].id == id) {
          selected = this.honeypots[i];
          break;
        }
      }

      if (selected == null) {
        console.log("error: could not find ID: " + id);
      } else {
        this.selectedHoneypot = selected;
        this.isSelectedId = id;
      }
    },
    getFreshHoneypotLink() {
      return this.config.honeypotsLink + "/0/" + this.limit;
    },
    getHoneypotLink() {
      let link =
        this.config.honeypotsLink + "/" + this.offset + "/" + this.limit;
      if (this.query) {
        link += "?q=" + encodeURIComponent(this.query);
      }

      return link;
    },
    setNextSelectedElement() {
      for (var i = 0; i < this.honeypots.length; i++) {
        if (this.honeypots[i].id == this.isSelectedId) {
          if (i + 1 < this.honeypots.length) {
            this.setSelected(this.honeypots[i + 1].id);
          } else {
            return false;
          }
          break;
        }
      }
      return true;
    },
    setPrevSelectedElement() {
      for (var i = this.honeypots.length - 1; i >= 0; i--) {
        if (this.honeypots[i].id == this.isSelectedId) {
          if (i - 1 >= 0) {
            this.setSelected(this.honeypots[i - 1].id);
          } else {
            return false;
          }
          break;
        }
      }
      return true;
    },
    loadNext() {
      this.offset += this.limit;
      this.$router.push(this.getHoneypotLink());
      this.loadHoneypots(true, function () {});
    },
    loadPrev() {
      if (this.offset - this.limit >= 0) {
        this.offset -= this.limit;
        this.$router.push(this.getHoneypotLink());
        this.loadHoneypots(false, function () {});
      }
    },

    loadHoneypots(selectFirst, callback) {
      this.isLoading = true;
      var url =
        this.config.backendAddress +
        "/honeypot/segment?offset=" +
        this.offset +
        "&limit=" +
        this.limit;
      if (this.query) {
        url += "&q=" + this.query;
      }
      fetch(url, {
        headers: {
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
          if (!response) {
            this.isLoading = false;
            return;
          }
          if (response.status == this.config.backendResultNotOk) {
            this.$toast.error(response.message);
          } else {
            this.honeypots = [];
            if (response.data) {
              for (var i = 0; i < response.data.length; i++) {
                const newHoneypot = Object.assign({}, response.data[i]);
                newHoneypot.parsed = {};
                newHoneypot.parsed.last_checkin = dateToString(
                  newHoneypot.last_checkin
                );
                newHoneypot.parsed.created_at = dateToString(
                  newHoneypot.created_at
                );
                this.honeypots.push(newHoneypot);
              }

              if (selectFirst) {
                this.setSelected(response.data[0].id);
              } else {
                this.setSelected(response.data[response.data.length - 1].id);
              }
            }
          }
          callback();
          this.isLoading = false;
        });
    },
  },
  beforeCreate() {
    this.selectedHoneypot = this.baseHoneypot;
  },
  created() {
    if (this.$route.params.limit) {
      this.limit = parseInt(this.$route.params.limit);
    }

    if (this.$route.params.offset) {
      this.offset = parseInt(this.$route.params.offset);
    }
  },
  mounted() {
    if (this.$route.query.q) {
      this.$refs.searchBar.setQuery(this.$route.query.q);
    } else {
      this.loadHoneypots(true, function(){});
    }
  },
};
</script>

<style scoped>
#date {
  width: 170px;
}

table {
  width: 100%;
}
.table tr.is-selected {
  background-color: #4e726d;
}
td {
  font-size: 13px;
}

i.pi-style {
  font-size: 2rem;
  color: #00d1b2;
}

i.pi-style-right {
  float: right;
}

.p-inputtext {
  width: 100%;
}
</style>
