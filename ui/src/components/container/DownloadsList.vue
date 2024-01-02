<template>
  <div class="columns">
    <div class="column is-three-fifths" style="margin-left: 15px">
      <table class="table is-hoverable" v-if="downloads.length > 0">
        <thead>
          <th>ID</th>
          <th>Request ID</th>
          <th>Orig URL</th>
          <th>Content Type</th>
          <th>Times Seen</th>
          <th>Created at</th>
        </thead>
        <tbody>
          <tr
            v-for="dl in downloads"
            @click="setSelectedDownload(dl.id)"
            :key="dl.id"
            :class="isSelectedId == dl.id ? 'is-selected' : ''"
          >
            <td> {{ dl.id }} </td>
            <td>
              <a :href="'/requests?q=id:' + dl.request_id">{{ dl.request_id }}</a>
            </td>
            <td>{{ dl.original_url }}</td>
            <td>{{ dl.content_type }}</td>
            <td>{{ dl.times_seen }}</td>
            <td>{{ dl.parsed.created_at }}</td>
          </tr>
        </tbody>
      </table>
    </div>
    <div class="column mright">
      <!--     <app-form @update-app="reloadDownloads()" :app="selectedApp"></app-form>
 -->
    </div>
  </div>
</template>

<script>
function dateToString(inDate) {
  const nd = new Date(Date.parse(inDate));
  return nd.toLocaleString();
}
//import DownloadForm from "./AppForm.vue";
export default {
  components: {
    // DownloadForm,
  },
  inject: ["config"],
  data() {
    return {
      downloads: [],
      selectedDownload: null,
      isSelectedId: 0,
      baseDownload: {
        id: 0,
        request_id: 0,
        original_url: "",
        content_type: "",
        parsed: {
          created_at: "",
        },
      },
    };
  },
  methods: {
    reloadDownloads() {
      this.loadDownloads();
    },
    setSelectedDownload(id) {
      var selected = null;
      for (var i = 0; i < this.downloads.length; i++) {
        if (this.downloads[i].id == id) {
          selected = this.downloads[i];
          break;
        }
      }

      if (selected == null) {
        console.log("error: could not find ID: " + id);
      } else {
        this.selectedDownload = selected;
        this.isSelectedId = id;
      }
    },
    loadDownloads() {
      fetch(this.config.backendAddress + "/downloads/all")
        .then((response) => response.json())
        .then((response) => {
          if (response.status == this.config.backendResultNotOk) {
            this.$toast.error(response.message);
          } else {
            this.downloads = [];
            if (response.data) {
              for (var i = 0; i < response.data.length; i++) {
                const newDownload = Object.assign({}, response.data[i]);
                newDownload.parsed = {};
                newDownload.parsed.created_at = dateToString(
                  newDownload.created_at
                );
                this.downloads.push(newDownload);
              }
            }
          }
        });
    },
  },
  beforeCreate() {
    this.selectedDownload = this.baseDownload;
  },
  created() {
    this.loadDownloads();
  },
};
</script>
