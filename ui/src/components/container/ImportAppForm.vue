<template>
  <div class="card">
    <FieldSet legend="Import app with rules" :toggleable="false">
     <input type="file" @change="handleFileUpload" />
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
