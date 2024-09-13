<template>
  <div class="columns">
    <div class="column is-three-fifths" style="margin-left: 15px">
      <DataSearchBar ref="searchBar" @search="performNewSearch" modelname="tag"></DataSearchBar>

      <table class="table is-hoverable" v-if="tags.length > 0">
        <thead>
          <th>ID</th>
          <th>Name</th>
          <th>HTML Color</th>
          <th>Description</th>
        </thead>
        <tbody>
          <tr
            v-for="t in tags"
            @click="setSelected(t.id)"
            :key="t.id"
            :class="isSelectedId == t.id ? 'is-selected' : ''"
          >
            <td>{{ t.id }}</td>
            <td>{{ t.name }}</td>
            <td><span :style="'background-color:#' + t.color_html">#{{ t.color_html }}</span></td>
            <td>{{ t.description }}</td>
          </tr>
        </tbody>
      </table>

      <i
        v-if="offset > 0"
        @click="loadPrev()"
        class="pi pi-arrow-left pi-style"
      ></i>
      <i
        v-if="tags.length == limit"
        @click="loadNext()"
        class="pi pi-arrow-right pi-style pi-style-right"
      ></i>
    </div>
    <div
      class="column mright"
      @focusin="keyboardDisabled = true"
      @focusout="keyboardDisabled = false"
    >
      <tag-form
        @update-tag="onUpdateTag"
        @delete-tag="onDeleteTag"
        @require-auth="$emit('require-auth')"
        :tag="selectedTag"
      ></tag-form>
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
  emits: ["require-auth"],
  inject: ["config"],
  data() {
    return {
      tags: [],
      selectedTag: null,
      isSelectedId: 0,
      query: null,
      limit: 24,
      offset: 0,
      keyboardDisabled: false,
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
  methods: {
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
        this.isSelectedId = id;
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
    setNextSelectedElement() {
      for (var i = 0; i < this.tags.length; i++) {
        if (this.tags[i].id == this.isSelectedId) {
          if (i + 1 < this.tags.length) {
            this.setSelected(this.tags[i + 1].id);
          } else {
            return false;
          }
          break;
        }
      }
      return true;
    },
    setPrevSelectedElement() {
      for (var i = this.tags.length - 1; i >= 0; i--) {
        if (this.tags[i].id == this.isSelectedId) {
          if (i - 1 >= 0) {
            this.setSelected(this.tags[i - 1].id);
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
      this.$router.push(this.getTagLink());
      this.loadTags(true, function () {});
    },
    loadPrev() {
      if (this.offset - this.limit >= 0) {
        this.offset -= this.limit;
        this.$router.push(this.getTagLink());
        this.loadTags(false, function () {});
      }
    },

    loadTags(selectFirst, callback) {
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
        });
    },
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
  },
  mounted() {

    if (this.$route.query.q) {
      this.$refs.searchBar.setQuery(this.$route.query.q);
    } else {
      this.loadTags(true, function () {});
    }

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
