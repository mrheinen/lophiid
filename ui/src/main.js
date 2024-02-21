import { createApp } from 'vue';
import { createRouter, createWebHistory } from 'vue-router';

// Allow toast messages.
import ToastPlugin from 'vue-toast-notification';
import 'vue-toast-notification/dist/theme-bootstrap.css';

import App from './App.vue';
import Config from './Config.js';
import ContentList from './components/container/ContentList.vue';
import RulesList from './components/container/RulesList.vue';
import RequestsList from './components/container/RequestsList.vue';
import AppsList from './components/container/AppsList.vue';
import DownList from './components/container/DownloadsList.vue';
import HoneyList from './components/container/HoneypotList.vue';
import QueryList from './components/container/QueryList.vue';
import TagList from './components/container/TagList.vue';
import PrimeVue from './../node_modules/primevue/config';

import CodeMirror from './../node_modules/vue-codemirror';
//import javascript from './../node_modules/@codemirror/lang-javascript';

import './../node_modules/bulma/css/bulma.css';
import './../node_modules/primevue/resources/themes/lara-light-blue/theme.css'
import './../node_modules/primeicons/primeicons.css';
import './../node_modules/highlight.js/styles/stackoverflow-light.css'
import './../node_modules/highlight.js/lib/common';

import store from './authStore.js';

import hljsVuePlugin from "./../node_modules/@highlightjs/vue-plugin";

const router = createRouter({
  history: createWebHistory(),
  routes: [
    {path: Config.contentLink, component: ContentList },
    {path: Config.contentSegmentLink, component: ContentList },
    {path: Config.rulesLink, component: RulesList },
    {path: Config.rulesSegmentLink, component: RulesList },
    {path: Config.appsLink, component: AppsList },
    {path: Config.appsSegmentLink, component: AppsList },
    {path: Config.downloadsLink, component: DownList },
    {path: Config.downloadsSegmentLink, component: DownList },
    {path: Config.honeypotsLink, component: HoneyList },
    {path: Config.honeypotsSegmentLink, component: HoneyList },
    {path: Config.storedqueryLink, component: QueryList },
    {path: Config.storedquerySegmentLink, component: QueryList },
    {path: Config.tagsLink, component: TagList },
    {path: Config.tagsSegmentLink, component: TagList },
    {path: Config.requestsLink, component: RequestsList },
    {path: Config.requestsSegmentLink, component: RequestsList, name: Config.requestsSegmentLinkName },
  ]
});

import AutoComplete from './../node_modules/primevue/autocomplete';
import Textarea from './../node_modules/primevue/textarea';
import InputText from './../node_modules/primevue/inputtext';
import InputNumber from './../node_modules/primevue/inputnumber';
import DropDown from './../node_modules/primevue/dropdown';
import ListBox from './../node_modules/primevue/listbox';
import FieldSet from './../node_modules/primevue/fieldset';
import Button from './../node_modules/primevue/button';
import ConfirmPopup from './../node_modules/primevue/confirmpopup';
import Dialog from './../node_modules/primevue/dialog';
import CheckBox from './../node_modules/primevue/checkbox';
import MenuBar from './../node_modules/primevue/menubar';
import MultiSelect from './../node_modules/primevue/multiselect';
import ColorPicker from './../node_modules/primevue/colorpicker';

import ConfirmationService from './../node_modules/primevue/confirmationservice';





const app = createApp(App);

app.component('AutoComplete', AutoComplete);
app.component('TextArea', Textarea);
app.component('InputText', InputText);
app.component('InputNumber', InputNumber);
app.component('DropDown', DropDown);
app.component('ListBox', ListBox);
app.component('FieldSet', FieldSet);
app.component('ConfirmPopup', ConfirmPopup);
app.component('PrimeButton', Button);
app.component('PrimeDialog', Dialog);
app.component('CheckBox', CheckBox);
app.component('MultiSelect', MultiSelect);
app.component('MenuBar', MenuBar);
app.component('ColorPicker', ColorPicker);
app.use(hljsVuePlugin);
app.use(router);
app.use(store);
app.use(PrimeVue);
app.use(ToastPlugin);
app.use(ConfirmationService);
app.use(CodeMirror, {
  // optional default global options
  autofocus: true,
  disabled: false,
  indentWithTab: true,
  tabSize: 2,
  placeholder: 'Code goes here...',
  extensions: [],
  theme: 'base16-dark'
})

app.mount('#app');


