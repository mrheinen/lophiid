<template>

  <div class="grid grid-rows-1 grid-cols-5 gap-4">
    <div class="col-span-3" style="mleft">
      <div class="rounded overflow-hidden shadow-lg">
        <DataTable
          :value="honeypots"
          tableStyle="min-width: 50rem"
          :metaKeySelection="true"
          dataKey="id"
          showGridlines
          compareSelectionBy="equals"
          v-model:selection="selectedHoneypot"
          selectionMode="single"
        >
          <template #header>
            <DataSearchBar
              ref="searchBar"
              :isloading="isLoading"
              @search="performNewSearch"
              modelname="honeypot"
            ></DataSearchBar>
          </template>
          <template #empty>No data matched. </template>
          <template #loading>Loading request data. Please wait. </template>

          <DataColumn field="id" header="ID" style="width: 4%">
          </DataColumn>

          <DataColumn header="IP" style="width: 5%">
            <template #body="slotProps">
              <a :href="'/requests?q=honeypot_ip:' + slotProps.data.ip">{{ slotProps.data.ip }}</a>
            </template>
          </DataColumn>
          <DataColumn field="version" header="Version" style="width: 10%">
          </DataColumn>
          <DataColumn field="parsed.created_at" header="First seen" style="width: 14%">
          </DataColumn>
          <DataColumn field="parsed.last_checkin" header="Last seen" style="width: 14%">
          </DataColumn>
          <DataColumn field="default_content_id" header="Default content"
          style="width: 8%">
          </DataColumn>
          <DataColumn field="request_count_last_day" header="# 24h"
          style="width: 8%">
          </DataColumn>

          <template #footer>
            <div class="flex justify-between items-center">
            <div>
            <i
              v-if="offset > 0"
              @click="loadPrev()"
              class="pi pi-arrow-left pi-style"
            ></i>
            <i
              v-if="offset == 0"
              class="pi pi-arrow-left pi-style-disabled"
            ></i>
            </div>
            <div>

            <FormSelect v-model="selectedLimit" @change="onChangeLimit" :options="limitOptions" placeholder="Limit" editable checkmark :highlightOnSelect="false" class="w-full md:w-56" />
            </div>
            <div>
            <i
              v-if="honeypots.length == limit"
              @click="loadNext()"
              class="pi pi-arrow-right pi-style pi-style-right"
            ></i>
            </div>
            </div>
          </template>

        </DataTable>
      </div>
    </div>
    <div class="colspan-2">
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
      selectedLimit: 21,
      limitOptions: [10, 20, 30, 40, 50],
      selectedHoneypot: null,
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
    onChangeLimit() {
      this.limit = this.selectedLimit
      this.loadHoneypots(true, function () {});
    },
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
    loadNext() {
      this.offset += this.limit;
      this.loadHoneypots(true, function () {});
    },
    loadPrev() {
      if (this.offset - this.limit >= 0) {
        this.offset -= this.limit;
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

    this.selectedLimit = this.limit;
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
