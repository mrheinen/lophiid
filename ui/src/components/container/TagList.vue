<template>
  <div class="grid grid-rows-1 grid-cols-5 gap-4">
    <div
      class="col-span-3"
      style="mleft"
    >
      <div class="rounded overflow-hidden shadow-lg">
        <DataTable
          v-model:selection="selectedTag"
          :value="tags"
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
              modelname="tag"
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
            field="name"
            header="Name"
            style="width: 10%"
          />
          <DataColumn
            header="HTML Color"
            style="width: 10%"
          >
            <template #body="slotProps">
              <span :style="'background-color:#' + slotProps.data.color_html">#{{ slotProps.data.color_html }}</span>
            </template>
          </DataColumn>
          <DataColumn
            field="description"
            header="Description"
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
                  v-if="tags.length == limit"
                  class="pi pi-arrow-right pi-style pi-style-right"
                  @click="loadNext()"
                />
              </div>
            </div>
          </template>
        </DataTable>
      </div>
    </div>
    <div class="col-span-2">
      <tag-form
        :tag="selectedTag"
        @update-tag="onUpdateTag"
        @delete-tag="onDeleteTag"
        @require-auth="$emit('require-auth')"
      />
    </div>
  </div>
</template>

<script>
import { dateToString } from "../../helpers.js";
import TagForm from "./TagForm.vue";
import DataSearchBar from "../DataSearchBar.vue";
export default {
  components: {
    TagForm,
    DataSearchBar,
  },
  inject: ["config"],
  emits: ["require-auth"],
  data() {
    return {
      tags: [],
      selectedTag: null,
      query: null,
      limit: 24,
      offset: 0,
      selectedLimit: 21,
      limitOptions: [10, 20, 30, 40, 50],
      isLoading: false,
      baseTag: {
        id: 0,
        query: "",
        record_count: 0,
        parsed: {
          last_ran_at: "",
        },
      },
    };
  },
  beforeCreate() {
    this.selectedTag = this.baseTag;
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
      this.loadTags(true, function () {});
    }
  },
  methods: {
    onChangeLimit() {
      this.limit = this.selectedLimit
      this.loadTags(true, function () {});
    },
    onUpdateTag(id) {
      const that = this;
      this.loadTags(true, function () {
        that.setSelected(id);
      });
    },
    onDeleteTag() {
      this.loadTags(true, function () {});
    },
    performNewSearch(query) {
      this.query = query;
      this.offset = 0;
      this.loadTags(true, function () {});
    },
    setSelected(id) {
      var selected = null;
      for (var i = 0; i < this.tags.length; i++) {
        if (this.tags[i].id == id) {
          selected = this.tags[i];
          break;
        }
      }

      if (selected == null) {
        console.log("error: could not find ID: " + id);
      } else {
        this.selectedTag = selected;
      }
    },
    getFreshTagLink() {
      return this.config.tagsSegmentLink + "/0/" + this.limit;
    },
    getTagLink() {
      let link =
        this.config.tagsSegmentLink +
        "/" +
        this.offset +
        "/" +
        this.limit;
      if (this.query) {
        link += "?q=" + encodeURIComponent(this.query);
      }

      return link;
    },
    loadNext() {
      this.offset += this.limit;
      this.loadTags(true, function () {});
    },
    loadPrev() {
      if (this.offset - this.limit >= 0) {
        this.offset -= this.limit;
        this.loadTags(false, function () {});
      }
    },

    loadTags(selectFirst, callback) {
      this.isLoading = true;
      var url =
        this.config.backendAddress +
        "/tag/segment?offset=" +
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
            this.tags = [];
            if (response.data && response.data.length > 0) {
              for (var i = 0; i < response.data.length; i++) {
                const newTag = Object.assign({}, response.data[i]);
                newTag.parsed = {};
                newTag.parsed.created_at = dateToString(newTag.created_at);
                this.tags.push(newTag);
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
</style>
