<template>
  <div class="columns">
    <div class="column is-three-fifths" style="margin-left: 15px;">

      <form @submit.prevent="performNewSearch()">
        <span class="p-input-icon-left" style="width: 100%">
          <i class="pi pi-search" />
          <InputText
            @focusin="keyboardDisabled = true"
            @focusout="keyboardDisabled = false"
            v-model="query"
            placeholder="Search"
          />
        </span>
      </form>

      <table class="table is-hoverable" v-if="honeypots.length > 0">
        <thead>
          <th>ID</th>
          <th>IP</th>
          <th>First seen</th>
          <th>Last checkin</th>
          <th>Default content</th>
        </thead>
        <tbody>
          <tr
            v-for="honeypot in honeypots"
            @click="setSelected(honeypot.id)"
            :key="honeypot.id"
            :class="isSelectedId == honeypot.id ? 'is-selected' : ''"
          >
            <td>{{ honeypot.id }}</td>
            <td>{{ honeypot.ip }}</td>
            <td>{{ honeypot.parsed.created_at }}</td>
            <td>{{ honeypot.parsed.last_checkin }}</td>
            <td>{{ honeypot.default_content_id }}</td>
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
    <div class="column mright" @focusin="keyboardDisabled = true" @focusout="keyboardDisabled = false">
     <honey-form @update-honeypot="reloadHoneypots()"
       :honeypot="selectedHoneypot"></honey-form>
    </div>
  </div>
</template>

<script>
function dateToString(inDate) {
  const nd = new Date(Date.parse(inDate));
  return nd.toLocaleString();
}
import HoneyForm from "./HoneypotForm.vue";
export default {
  components: {
    HoneyForm,
  },
  inject: ["config"],
  data() {
    return {
      honeypots: [],
      selected: null,
      isSelectedId: 0,
      query: null,
      limit: 24,
      offset: 0,
      keyboardDisabled: false,
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
    performNewSearch() {
      this.offset = 0;
      this.loadHoneypots(true);
    },
    reloadHoneypots() {
      this.loadHoneypots(true);
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
      return this.config.honeypotSegmentLink + "/0/" + this.limit;
    },
    getHoneypotLink() {
      let link =
        this.config.honeypotSegmentLink + "/" + this.offset + "/" + this.limit;
      if (this.query) {
        link += "?q=" + this.query;
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
      this.loadHoneypots(true);
    },
    loadPrev() {
      if (this.offset - this.limit >= 0) {
        this.offset -= this.limit;
        this.$router.push(this.getHoneypotLink());
        this.loadHoneypots(false);
      }
    },

    loadHoneypots(selectFirst) {
      var url = this.config.backendAddress + "/honeypot/segment?offset=" +
        this.offset + "&limit=" + this.limit;
      if (this.query) {
        url += "&q=" + this.query;
      }
      fetch(url)
        .then((response) => response.json())
        .then((response) => {
          if (response.status == this.config.backendResultNotOk) {
            this.$toast.error(response.message);
          } else {
            this.honeypots = [];
            if (response.data) {
              for (var i = 0; i < response.data.length; i++) {
                const newHoneypot = Object.assign({}, response.data[i]);
                newHoneypot.parsed = {};
                newHoneypot.parsed.last_checkin = dateToString(newHoneypot.last_checkin);
                newHoneypot.parsed.created_at = dateToString(newHoneypot.created_at);
                this.honeypots.push(newHoneypot);
              }

              if (selectFirst) {
                this.setSelected(response.data[0].id);
              } else {
                this.setSelected(response.data[response.data.length - 1].id);
              }
            }
          }
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

    if (this.$route.query.q) {
      this.query = this.$route.query.q;
    }

    this.loadHoneypots(true);
  },
  mounted() {
    const that = this;
    window.addEventListener("keyup", function (event) {
      if (that.keyboardDisabled) {
        return;
      }
      if (event.key == "j") {
        if (!that.setPrevSelectedElement()) {
          that.loadPrev();
        }
      } else if (event.key == "k") {
        if (!that.setNextSelectedElement()) {
          that.loadNext();
        }
      }
    });
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
