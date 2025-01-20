<template>
  <div class="columns">
    <div class="column is-three-fifths" style="margin-left: 15px;">

      <div class="card">
        <DataTable
          :value="contents"
          tableStyle="min-width: 50rem"
          :metaKeySelection="true"
          dataKey="id"
          showGridlines
          compareSelectionBy="equals"
          v-model:selection="selectedContent"
          selectionMode="single"
        >
          <template #header>
            <DataSearchBar
              ref="searchBar"
              :isloading="isLoading"
              @search="performNewSearch"
              modelname="content"
            ></DataSearchBar>
          </template>
          <template #empty>No data matched. </template>
          <template #loading>Loading request data. Please wait. </template>

          <DataColumn field="id" header="ID" style="width: 4%">
          </DataColumn>
          <DataColumn field="parsed.name" header="Description" style="width: 35%">
            <template #body="slotProps">
              <span v-if="slotProps.data.script.length > 0" class="pi=play">
              </span>
              {{ slotProps.data.parsed.name }}
            </template>
          </DataColumn>
          <DataColumn field="content_type" header="Content Type" style="width: 25%">
          </DataColumn>
          <DataColumn field="server" header="Server" style="width: 20%">
          </DataColumn>
          <DataColumn field="parsed.updated_at" header="Last update" style="width: 25%">
          </DataColumn>

          <DataColumn header="Actions" style="width: 5%">
            <template #body="slotProps">
              <a
                :href="config.rulesLink + '?content_id:' + slotProps.data.id"
              >
                <i
                  title="Create a rule for this"
                  class="pi pi-arrow-circle-right"
                ></i>
              </a>
              &nbsp;
               <a :href="config.requestsLink + '?q=content_id:' + slotProps.data.id">
                  <i
                    title="View requests that got this content"
                    class="pi pi-search"
                  ></i>
                </a>
            </template>
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

            <FormSelect v-model="selectedLimit" @change="onChangeLimit()" :options="limitOptions" placeholder="Limit" editable checkmark :highlightOnSelect="false" class="w-full md:w-56" />
            </div>
            <div>
            <i
              v-if="contents.length == limit"
              @click="loadNext()"
              class="pi pi-arrow-right pi-style pi-style-right"
            ></i>
            </div>
            </div>
          </template>

        </DataTable>
      </div>
    </div>
    <div class="column restrict-width mright">
      <content-form
        @update-content="onUpdateContent"
        @deleted-content="onDeleteContent"
        @require-auth="$emit('require-auth')"
        :content="selectedContent"
      ></content-form>
    </div>
  </div>
</template>

<script>
import { truncateString, dateToString } from "../../helpers.js";

import ContentForm from "./ContentForm.vue";
import DataSearchBar from "../DataSearchBar.vue";
export default {
  components: {
    ContentForm,
    DataSearchBar,
  },
  inject: ["config"],
  emits: ["require-auth"],
  data() {
    return {
      contents: [],
      selectedContent: null,
      isSelectedId: 0,
      limit: 21,
      selectedLimit: 21,
      limitOptions: [10, 20, 30, 40, 50],
      offset: 0,
      query: null,
      isLoading: false,
      baseContent: {
        id: 0,
        name: "",
        server: "",
        content_type: "",
        data: "",
        time_created: "",
        time_updated: "",
      },
    };
  },
  methods: {
    performNewSearch(query) {
      this.query = query;
      this.offset = 0;
      this.loadContents(true, function(){});
    },
    onChangeLimit() {
      this.limit = this.selectedLimit
      this.loadContents(true, function () {});
    },

    onDeleteContent() {
      console.log("Deleted content");
      this.reloadContents();
    },
    onUpdateContent(id) {
      console.log("Updated ID " + id);
      const that = this
      this.loadContents(true, function(){
        that.setSelectedContent(id)
      });
    },
    reloadContents() {
      this.loadContents(true, function(){});
    },
    getFreshRequestLink() {
      return this.config.requestsLink + "/0/" + this.limit;
    },
    getContentLink() {
      let link =
        this.config.contentLink + "/" + this.offset + "/" + this.limit;
      if (this.query) {
        link += "?q=" + encodeURIComponent(this.query);
      }

      return link;
    },
    loadNext() {
      this.offset += this.limit;
      this.loadContents(true, function(){});
    },
    loadPrev() {
      if (this.offset - this.limit >= 0) {
        this.offset -= this.limit;
        this.loadContents(false, function(){});
      }
    },
    setSelectedContent(id) {
      var selected = null;
      for (var i = 0; i < this.contents.length; i++) {
        if (this.contents[i].id == id) {
          selected = this.contents[i];
          break;
        }
      }

      if (selected == null) {
        console.log("error: could not find ID: " + id);
      } else {
        this.selectedContent = selected;
        this.isSelectedId = id;
      }
    },
    loadContents(selectFirst, callback) {
      this.isLoading = true;
      var url = this.config.backendAddress + "/content/segment?offset=" +
        this.offset + "&limit=" + this.limit;
      if (this.query) {
        url += "&q=" + this.query;
      }

      fetch(url, { headers: {
        'API-Key': this.$store.getters.apiToken,
      }})
        .then((response) => {
          if (response.status == 403) {
            this.$emit('require-auth');
            return null;
          } else {
            return response.json()
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
            this.contents = [];
            if (response.data) {
              for (var i = 0; i < response.data.length; i++) {
                const newContent = Object.assign({}, response.data[i]);

                newContent.parsed = {};
                newContent.parsed.created_at = dateToString(
                  newContent.created_at
                );
                newContent.parsed.updated_at = dateToString(
                  newContent.updated_at
                );

                newContent.parsed.name = truncateString(newContent.name, 60)

                if (newContent.data) {
                  newContent.data = atob(newContent.data);
                }
                this.contents.push(newContent);
              }

              if (selectFirst) {
                this.setSelectedContent(response.data[0].id);
              } else {
                this.setSelectedContent(response.data[response.data.length - 1].id);
              }
            }
          }
          callback();
          this.isLoading = false;
        });
    },
  },
  created() {

    this.selectedContent = this.baseContent;
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
      this.query = this.$route.query.q;
      this.$refs.searchBar.setQuery(this.$route.query.q);
    }
    this.loadContents(true, function(){})
  },
};
</script>

<style scoped>
.restrict-width {
  width: 700px;
}
.table tr.is-selected {
  background-color: #4e726d;
}

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

.default {
  font-weight: bold;
  font-size: 9px;
  color: #ab5a54;
}

</style>
