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
            <td><span v-if="content.script.length > 0" class="pi pi-play"></span>{{ content.name }} <b class="default" v-if="content.is_default">default</b>

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
        :content="selectedContent"
      ></content-form>
    </div>
  </div>
</template>

<script>
function dateToString(inDate) {
  const nd = new Date(Date.parse(inDate));
  return nd.toLocaleString();
}
import ContentForm from "./ContentForm.vue";
export default {
  components: {
    ContentForm,
  },
  inject: ["config"],
  data() {
    return {
      contents: [],
      selectedContent: null,
      isSelectedId: 0,
      limit: 24,
      offset: 0,
      query: null,
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
    performNewSearch() {
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
        link += "?q=" + this.query;
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
      var url = this.config.backendAddress + "/content/segment?offset=" +
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

    if (this.$route.query.q) {
      this.query = this.$route.query.q;
    }
    this.loadContents(true, function(){})
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
.restrict-width {
  width: 700px;
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
