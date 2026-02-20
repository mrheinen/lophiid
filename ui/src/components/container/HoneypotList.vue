<template>
  <div class="list-layout">
    <div class="list-table-wrap">
        <DataTable
          v-model:selection="selectedHoneypot"
          :value="honeypots"
          table-style="min-width: 50rem"
          :meta-key-selection="true"
          data-key="id"
          show-gridlines
          compare-selection-by="equals"
          selection-mode="single"
        >
          <template #header>
            <DataSearchBar
              ref="searchBar"
              :isloading="isLoading"
              modelname="honeypot"
              @search="performNewSearch"
            />
          </template>
          <template #empty>
            No data matched.
          </template>
          <template #loading>
            Loading request data. Please wait.
          </template>

          <DataColumn
            field="id"
            header="ID"
            style="width: 4%"
          />

          <DataColumn
            header="IP"
            style="width: 5%"
          >
            <template #body="slotProps">
              <a :href="'/requests?q=honeypot_ip:' + slotProps.data.ip">{{ slotProps.data.ip }}</a>
            </template>
          </DataColumn>
          <DataColumn
            field="version"
            header="Version"
            style="width: 10%"
          />
          <DataColumn
            field="parsed.created_at"
            header="First seen"
            class="col-shrink"
          />
          <DataColumn
            field="parsed.last_checkin"
            header="Last seen"
            class="col-shrink"
          />
          <DataColumn
            field="default_content_id"
            header="Default content"
            style="width: 8%"
          />
          <DataColumn
            field="request_count_last_day"
            header="# 24h"
            style="width: 8%"
          />

          <template #footer>
            <div class="flex justify-between items-center">
              <div>
                <i
                  v-if="offset > 0"
                  class="pi pi-arrow-left pi-style"
                  @click="loadPrev()"
                />
                <i
                  v-if="offset == 0"
                  class="pi pi-arrow-left pi-style-disabled"
                />
              </div>
              <div>
                <FormSelect
                  v-model="selectedLimit"
                  :options="limitOptions"
                  placeholder="Limit"
                  editable
                  checkmark
                  :highlight-on-select="false"
                  class="w-full md:w-56"
                  @change="onChangeLimit"
                />
              </div>
              <div>
                <i
                  v-if="honeypots.length == limit"
                  class="pi pi-arrow-right pi-style pi-style-right"
                  @click="loadNext()"
                />
              </div>
            </div>
          </template>
        </DataTable>
    </div>
    <div class="list-form-wrap">
      <honey-form
        :honeypot="selectedHoneypot"
        @update-honeypot="onUpdateHoneypot"
        @delete-honeypot="onDeleteHoneypot"
        @require-auth="$emit('require-auth')"
      />
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
  inject: ["config"],
  emits: ["require-auth"],
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
};
</script>

<style scoped>
.p-inputtext {
  width: 100%;
}
</style>
