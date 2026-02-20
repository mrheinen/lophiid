<template>
  <div>
    <InfoCard mylabel="Import app with rules">
      <template #default>
        <p style="margin-bottom: 0.75rem;">
          Select a YAML file to import an app with all its rules and contents.
          Only import trusted files and verify them manually before importing.
        </p>
        <input
          ref="fileInput"
          type="file"
          accept=".yaml,.yml"
          class="file-input-hidden"
          @change="handleFileUpload"
        >
        <PrimeButton
          :label="selectedFile ? selectedFile.name : 'Choose YAML file...'"
          icon="pi pi-file"
          severity="secondary"
          outlined
          @click="$refs.fileInput.click()"
        />
        <div class="flex gap-2 mt-3">
          <PrimeButton
            label="Import"
            icon="pi pi-download"
            @click="submitForm()"
          />
        </div>
      </template>
    </InfoCard>
  </div>
</template>


<script>
  export default {
    inject: ["config"],
    emits: ["form-done"],
    data() {
      return {
        selectedFile: "",
        localData: "",
      }
    },
    methods: {
      handleFileUpload(event) {
        const reader = new FileReader();
        var that = this;
        reader.onload = function() {
          that.localData = reader.result;
        }
        reader.onerror = function() {
          that.$toast.error("can't read file");
        }

        this.selectedFile = event.target.files[0];
        reader.readAsText(this.selectedFile);
      },
      submitForm() {

        if (this.selectedFile == "" || this.localData == "") {
          this.$toast.error("Select a file first");
          return;
        }
        fetch(this.config.backendAddress + "/app/import", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "API-Key": this.$store.getters.apiToken,
          },
          body: this.localData,
        })
          .then((response) => response.json())
          .then((response) => {
            if (response.status == this.config.backendResultNotOk) {
              this.$toast.error(response.message);
            } else {
              this.$toast.success("Import done");
              this.$emit("form-done");
            }
          });
      },
    },

  }

</script>

<style scoped>
.file-input-hidden {
  display: none;
}
</style>
