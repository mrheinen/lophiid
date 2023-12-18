<template>
  <div class="columns">
    <div class="column is-three-fifths">
      <table class="table is-hoverable" style="margin-left: 15px;" v-if="contents.length > 0">
        <thead>
          <th>ID</th>
          <th>Description</th>
          <th>Content type</th>
          <th>Server</th>
          <th>Date created</th>
          <th>Date updated</th>
        </thead>
        <tbody>
          <tr
            v-for="content in contents"
            @click="setSelectedContent(content.id)"
            :key="content.id"
            :class="isSelectedId == content.id ? 'is-selected' : ''"
          >
            <td>{{ content.id }}</td>
            <td>{{ content.name }}</td>
            <td>{{ content.content_type }}</td>
            <td>{{ content.server }}</td>
            <td>{{ content.parsed.created_at }}</td>
            <td>{{ content.parsed.updated_at }}</td>
          </tr>
        </tbody>
      </table>
    </div>
    <div class="column restrict-width mright">
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
    onDeleteContent() {
      console.log("Deleted content");
      this.reloadContents();
    },
    onUpdateContent(id) {
      console.log("Updated ID " + id);
      this.reloadContents();
    },
    reloadContents() {
      this.loadContents(function(){});
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
    loadContents(callback) {
      fetch(this.config.backendAddress + "/content/all")
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
    const maybeSetID = this.$route.params.contentId;
    const that = this;
    this.loadContents(function() {
      if (maybeSetID) {
        that.setSelectedContent(maybeSetID);
      }
    });
  },
};
</script>

<style scoped>
.restrict-width {
  width: 700px;
}
</style>
