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
