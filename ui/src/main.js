import { createApp } from 'vue';
import { createRouter, createWebHistory } from 'vue-router';

import './index.css'

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
import EventsList from './components/container/EventsList.vue';
import TagList from './components/container/TagList.vue';
import YaraList from './components/container/YaraList.vue';
import GlobalStats from './components/container/GlobalStats.vue';
import InfoCard from './components/cards/InfoCard.vue';
import PrimeVue from './../node_modules/primevue/config';

import CodeMirror from './../node_modules/vue-codemirror';

import './../node_modules/@fontsource/roboto/index.css';
import './../node_modules/@fontsource/source-sans-pro/400.css';
//import './../node_modules/bulma/css/bulma.css';
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
    {path: Config.eventLink, component: EventsList },
    {path: Config.eventSegmentLink, component: EventsList },
    {path: Config.yaraLink, component: YaraList },
    {path: Config.yaraSegmentLink, component: YaraList },
    {path: Config.statsLink, component: GlobalStats },
  ]
});

import AutoComplete from './../node_modules/primevue/autocomplete';
import Textarea from './../node_modules/primevue/textarea';
import InputText from './../node_modules/primevue/inputtext';
import InputNumber from './../node_modules/primevue/inputnumber';
import Select from './../node_modules/primevue/select';
import Badge from './../node_modules/primevue/badge';
import ListBox from './../node_modules/primevue/listbox';
import FieldSet from './../node_modules/primevue/fieldset';
import Button from './../node_modules/primevue/button';
import ConfirmPopup from './../node_modules/primevue/confirmpopup';
import Dialog from './../node_modules/primevue/dialog';
import CheckBox from './../node_modules/primevue/checkbox';
import MenuBar from './../node_modules/primevue/menubar';
import MultiSelect from './../node_modules/primevue/multiselect';
import ColorPicker from './../node_modules/primevue/colorpicker';
import PopOver from './../node_modules/primevue/popover';
import IconField from './../node_modules/primevue/iconfield';
import InputIcon from './../node_modules/primevue/inputicon';
import DataTable from './../node_modules/primevue/datatable';
import Column from './../node_modules/primevue/column';
import Skeleton from './../node_modules/primevue/skeleton';
import Tabs from './../node_modules/primevue/tabs';
import TabList from './../node_modules/primevue/tablist';
import Tab from './../node_modules/primevue/tab';
import TabPanels from './../node_modules/primevue/tabpanels';
import TabPanel from './../node_modules/primevue/tabpanel';
import ConfirmationService from './../node_modules/primevue/confirmationservice';
import Chart from './../node_modules/primevue/chart';



import Lara from '@primevue/themes/lara';
import { definePreset } from '@primevue/themes';


const MyPreset = definePreset(Lara, {
    semantic: {
        primary: {
            50: '{amber.50}',
            100: '{amber.100}',
            200: '{amber.200}',
            300: '{amber.300}',
            400: '{amber.400}',
            500: '{amber.500}',
            600: '{amber.600}',
            700: '{amber.700}',
            800: '{amber.800}',
            900: '{amber.900}',
            950: '{amber.950}'
        }
    }
});


const app = createApp(App);

app.component('PrimeTabs', Tabs);
app.component('PrimeTab', Tab);
app.component('TabList', TabList);
app.component('TabPanels', TabPanels);
app.component('PrimeBadge', Badge);
app.component('TabPanel', TabPanel);
app.component('AutoComplete', AutoComplete);
app.component('TextArea', Textarea);
app.component('InputText', InputText);
app.component('InputNumber', InputNumber);
app.component('FormSelect', Select);
app.component('ListBox', ListBox);
app.component('FieldSet', FieldSet);
app.component('ConfirmPopup', ConfirmPopup);
app.component('PrimeButton', Button);
app.component('PrimeDialog', Dialog);
app.component('CheckBox', CheckBox);
app.component('MultiSelect', MultiSelect);
app.component('MenuBar', MenuBar);
app.component('ColorPicker', ColorPicker);
app.component('DataTable', DataTable);
app.component('DataColumn', Column);
app.component('DataSkeleton', Skeleton);
app.component('IconField', IconField);
app.component('InputIcon', InputIcon);
app.component('PopOver', PopOver);
app.component('PrimeChart', Chart);
app.component('InfoCard', InfoCard);
app.use(hljsVuePlugin);
app.use(router);
app.use(store);
app.use(PrimeVue, {
    theme: {
        preset: MyPreset
    }
});
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
