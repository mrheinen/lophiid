<template>
  <div
    v-for="yara in data"
    :key="yara.id"
  >
    <label class="label">{{ yara.identifier }}</label>
    <table>
      <tbody>
        <tr v-if="yara.description">
          <th id="yarath">
            Description
          </th>
          <td id="yaratd">
            {{ yara.description }}
          </td>
        </tr>
        <tr v-if="yara.author">
          <th id="yarath">
            Author
          </th>
          <td id="yaratd">
            {{ yara.author }}
          </td>
        </tr>
        <tr v-if="yara.date">
          <th id="yarath">
            Date
          </th>
          <td id="yaratd">
            {{ yara.date }}
          </td>
        </tr>
        <tr v-if="yara.reference">
          <th id="yarath">
            Reference
          </th>
          <td id="yaratd">
            <a
              :href="yara.reference"
              target="_blank"
            >{{ yara.reference }}</a>
          </td>
        </tr>
        <tr v-if="yara.malpedia_reference">
          <th id="yarath">
            Malpedia reference
          </th>
          <td id="yaratd">
            <a
              :href="yara.malpedia_reference"
              target="_blank"
            >{{ yara.malpedia_reference }}</a>
          </td>
        </tr>
        <tr v-if="yara.malpedia_license">
          <th id="yarath">
            Malpedia license
          </th>
          <td id="yaratd">
            {{ yara.malpedia_license }}
          </td>
        </tr>
        <tr v-if="yara.malpedia_sharing">
          <th id="yarath">
            Malpedia sharing
          </th>
          <td id="yaratd">
            {{ yara.malpedia_sharing }}
          </td>
        </tr>
      </tbody>
    </table>
    <hr>
  </div>
</template>

<script>
export default {
  props: {
    "data": {
      type: Object,
      required: true
    }
  },
  data() {
    return {
    };
  },
  watch: {
  },
  methods: {
  },
}
</script>


<style scoped>
table {
  border-collapse: collapse;
}

th,
td {
  padding-top: 2px;
  padding-bottom: 2px;
  padding-right: 8px;
  text-align: left !important;
}

th {
  color: #616060;
}

.pointer {
  cursor: pointer;
}

#yarath {
  width: 140px;
}

</style>
