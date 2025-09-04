<template>
  <div class="rounded overflow-hidden shadow-lg">
    <FieldSet legend="Import app with rules" :toggleable="false">
     <p>Select a yaml file to import an app with all it's rules and contents.</p>
     <p>You should only import trusted files and verify them manually before importing them.</p>
     <br/>
     <input type="file" @change="handleFileUpload" accept=".yaml,.yml"  />
    </FieldSet>

    <PrimeButton
      label="Import"
      @click="submitForm()"
    >
    </PrimeButton>
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
        
        this.$toast.info("Importing app...");
        
        fetch(this.config.backendAddress + "/app/import", {
          method: "POST",
          headers: {
            "Content-Type": "text/plain",
            "API-Key": this.$store.getters.apiToken,
          },
          body: this.localData,
        })
          .then((response) => {
            if (!response.ok) {
              if (response.status === 413) {
                throw new Error("File too large. Maximum file size is 50MB.");
              } else if (response.status === 504) {
                throw new Error("Request timed out. The file may be too large to process.");
              }
              throw new Error(`HTTP error! status: ${response.status}`);
            }
            return response.json();
          })
          .then((response) => {
            if (response.status == this.config.backendResultNotOk) {
              this.$toast.error("Import failed: " + response.message);
              console.error("Import error:", response);
            } else {
              this.$toast.success("Import done");
              this.$emit("form-done");
            }
          })
          .catch((error) => {
            console.error("Import request failed:", error);
            if (error.message.includes("Failed to fetch")) {
              this.$toast.error("Import failed: Network error. The file may be too large.");
            } else {
              this.$toast.error("Import failed: " + error.message);
            }
          });
      },
    },

  }

</script>
