export function copyToClipboardHelper(textToCopy) {
    // Navigator clipboard api needs a secure context (https)
    if (navigator.clipboard && window.isSecureContext) {
      navigator.clipboard.writeText(textToCopy);
    } else {
      // Use the 'out of viewport hidden text area' trick
      const textArea = document.createElement("textarea");
      textArea.value = textToCopy;

      // Move textarea out of the viewport so it's not visible
      textArea.style.position = "absolute";
      textArea.style.left = "-999999px";

      document.body.prepend(textArea);
      textArea.select();

      try {
        document.execCommand('copy');
      } catch (error) {
        console.error(error);
      } finally {
        textArea.remove();
      }
    }
  }

export function truncateString(str, maxlen) {
  if (str.length > maxlen) {
    return str.substring(0, maxlen) + "...";
  }
  return str;
}

// Decodes unicode strings in the given encodesString.
export function decodeUnicodeString(encodedString) {
  const unicodeRegex = /\\u([0-9a-fA-F]{4})/g;
  const decodedString = encodedString.replace(unicodeRegex, (match, codePoint) => {
    return String.fromCharCode(parseInt(codePoint, 16));
  });

  return decodedString;
}

export function dateToString(inDate) {
  var options = {
    year: "2-digit",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  };
  const nd = new Date(Date.parse(inDate));
  return nd.toLocaleDateString("en-US", options);
}

export const sharedMixin = {
  data: function () {
    return {
      selectedWhois: null,
    }
  },
  methods: {

    // LoadWhois loads the whois for IP.
    //
    // Emits: require-auth
    // Sets:  this.selectedWhois
    loadWhois(ip) {
      fetch(this.config.backendAddress + "/whois/ip", {
        method: "POST",
        headers: {
          "API-Key": this.$store.getters.apiToken,
          "Content-Type": "application/x-www-form-urlencoded",
        },
        body: "ip=" + ip,
      })
        .then((response) => {
          if (response.status == 403) {
            this.$emit("require-auth");
          } else {
            return response.json();
          }
        })
        .then((response) => {
          if (response.status == this.config.backendResultNotOk) {
            this.$toast.error(response.message);
            this.selectedWhois = null;
          } else {
            if (response.data) {
              this.selectedWhois = response.data;
            } else {
              this.selectedWhois = null;
            }
          }
        });
    }
  }
};

export function getDateMinusMonths(monthsToSubtract) {
  const date = new Date();
  date.setMonth(date.getMonth() - monthsToSubtract);
  const day = String(date.getDate()).padStart(2, '0');
  const month = String(date.getMonth() + 1).padStart(2, '0');
  const year = date.getFullYear();

  return month + "/" + day + "/" + year;
}
