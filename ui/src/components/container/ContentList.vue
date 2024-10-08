<template>
  <div class="columns">
    <div class="column is-three-fifths" style="margin-left: 15px;">
      <DataSearchBar ref="searchBar" :isLoading="isLoading" @search="performNewSearch" modelname="content"></DataSearchBar>

      <table class="table is-hoverable" v-if="contents.length > 0">
        <thead>
          <th>ID</th>
          <th>Description</th>
          <th>Content type</th>
          <th>Server</th>
          <th>Date updated</th>
          <th>Actions</th>
        </thead>
        <tbody>
          <tr
            v-for="content in contents"
            @click="setSelectedContent(content.id)"
            :key="content.id"
            :class="isSelectedId == content.id ? 'is-selected' : ''"
          >
            <td>{{ content.id }}</td>
            <td><span v-if="content.script.length > 0" class="pi
                pi-play"></span>{{ content.parsed.name }} <b class="default" v-if="content.is_default">default</b>

            </td>
            <td>{{ content.content_type }}</td>
            <td>{{ content.server }}</td>
            <td>{{ content.parsed.updated_at }}</td>
            <td>
              <a :href="'/rules?content_id=' + content.id">
                <i
                  title="Create a rule for this"
                  class="pi pi-arrow-circle-right"
                ></i>
              </a>
              &nbsp;
              <a :href="'/requests?q=content_id:' + content.id">
                  <i
                    title="View requests that got this content"
                    class="pi pi-search"
                  ></i>
                </a>
            </td>
          </tr>
        </tbody>
      </table>

      <i
        v-if="offset > 0"
        @click="loadPrev()"
        class="pi pi-arrow-left pi-style"
      ></i>
      <i
        v-if="contents.length == limit"
        @click="loadNext()"
        class="pi pi-arrow-right pi-style pi-style-right"
      ></i>

    </div>
    <div class="column restrict-width mright" @focusin="keyboardDisabled = true" @focusout="keyboardDisabled = false">
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
      limit: 24,
      offset: 0,
      query: null,
      isLoading: false,
      keyboardDisabled: false,
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

    setNextSelectedElement() {
      for (var i = 0; i < this.contents.length; i++) {
        if (this.contents[i].id == this.isSelectedId) {
          if (i + 1 < this.contents.length) {
            this.setSelectedContent(this.contents[i + 1].id);
          } else {
            return false;
          }
          break;
        }
      }
      return true;
    },
    setPrevSelectedElement() {
      for (var i = this.contents.length - 1; i >= 0; i--) {
        if (this.contents[i].id == this.isSelectedId) {
          if (i - 1 >= 0) {
            this.setSelectedContent(this.contents[i - 1].id);
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
      this.$router.push(this.getContentLink());
      this.loadContents(true, function(){});
    },
    loadPrev() {
      if (this.offset - this.limit >= 0) {
        this.offset -= this.limit;
        this.$router.push(this.getContentLink());
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

                newContent.parsed.name = truncateString(newContent.name, 40)

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
  beforeCreate() {
    this.selectedContent = this.baseContent;
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
      this.query = this.$route.query.q;
      this.$refs.searchBar.setQuery(this.$route.query.q);
    }
    this.loadContents(true, function(){})

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
