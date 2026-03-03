import { createApp } from 'vue';
import { createRouter, createWebHistory } from 'vue-router';

import './index.css';

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
import RuleGroupList from './components/container/RuleGroupList.vue';
import GlobalStats from './components/container/GlobalStats.vue';
import UriStats from './components/container/UriStats.vue';
import InfoCard from './components/cards/InfoCard.vue';

import PrimeVue from 'primevue/config';
import CodeMirror from 'vue-codemirror';
import hljsVuePlugin from '@highlightjs/vue-plugin';

import '@fontsource/roboto/index.css';
import '@fontsource/source-sans-pro/400.css';
import 'primeicons/primeicons.css';
import 'highlight.js/styles/stackoverflow-light.css';
import 'highlight.js/lib/common';

import store from './authStore.js';

// PrimeVue component imports
import AutoComplete from 'primevue/autocomplete';
import Textarea from 'primevue/textarea';
import InputText from 'primevue/inputtext';
import InputNumber from 'primevue/inputnumber';
import InputGroup from 'primevue/inputgroup';
import InputGroupAddon from 'primevue/inputgroupaddon';
import Select from 'primevue/select';
import Badge from 'primevue/badge';
import ListBox from 'primevue/listbox';
import FieldSet from 'primevue/fieldset';
import Button from 'primevue/button';
import ConfirmPopup from 'primevue/confirmpopup';
import Dialog from 'primevue/dialog';
import CheckBox from 'primevue/checkbox';
import MenuBar from 'primevue/menubar';
import MultiSelect from 'primevue/multiselect';
import ColorPicker from 'primevue/colorpicker';
import PopOver from 'primevue/popover';
import IconField from 'primevue/iconfield';
import InputIcon from 'primevue/inputicon';
import DataTable from 'primevue/datatable';
import Column from 'primevue/column';
import Skeleton from 'primevue/skeleton';
import Tabs from 'primevue/tabs';
import TabList from 'primevue/tablist';
import Tab from 'primevue/tab';
import TabPanels from 'primevue/tabpanels';
import TabPanel from 'primevue/tabpanel';
import ConfirmationService from 'primevue/confirmationservice';
import Chart from 'primevue/chart';
import Card from 'primevue/card';
import Tag from 'primevue/tag';
import Toolbar from 'primevue/toolbar';
import ProgressBar from 'primevue/progressbar';
import Tooltip from 'primevue/tooltip';
import Divider from 'primevue/divider';

import Lara from '@primevue/themes/lara';
import { definePreset } from '@primevue/themes';

const LophiidPreset = definePreset(Lara, {
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
        },
        colorScheme: {
            light: {
                surface: {
                    0: '#ffffff',
                    50: '{slate.50}',
                    100: '{slate.100}',
                    200: '{slate.200}',
                    300: '{slate.300}',
                    400: '{slate.400}',
                    500: '{slate.500}',
                    600: '{slate.600}',
                    700: '{slate.700}',
                    800: '{slate.800}',
                    900: '{slate.900}',
                    950: '{slate.950}'
                }
            }
        }
    }
});

const router = createRouter({
  history: createWebHistory(),
  routes: [
    { path: '/', redirect: Config.requestsLink },
    { path: Config.contentLink, component: ContentList },
    { path: Config.contentSegmentLink, component: ContentList },
    { path: Config.rulesLink, component: RulesList },
    { path: Config.rulesSegmentLink, component: RulesList },
    { path: Config.appsLink, component: AppsList },
    { path: Config.appsSegmentLink, component: AppsList },
    { path: Config.downloadsLink, component: DownList },
    { path: Config.downloadsSegmentLink, component: DownList },
    { path: Config.honeypotsLink, component: HoneyList },
    { path: Config.honeypotsSegmentLink, component: HoneyList },
    { path: Config.storedqueryLink, component: QueryList },
    { path: Config.storedquerySegmentLink, component: QueryList },
    { path: Config.tagsLink, component: TagList },
    { path: Config.tagsSegmentLink, component: TagList },
    { path: Config.requestsLink, component: RequestsList },
    { path: Config.requestsSegmentLink, component: RequestsList, name: Config.requestsSegmentLinkName },
    { path: Config.eventLink, component: EventsList },
    { path: Config.eventSegmentLink, component: EventsList },
    { path: Config.yaraLink, component: YaraList },
    { path: Config.yaraSegmentLink, component: YaraList },
    { path: Config.ruleGroupsLink, component: RuleGroupList },
    { path: Config.ruleGroupsSegmentLink, component: RuleGroupList },
    { path: Config.statsLink, component: GlobalStats },
    { path: Config.uriStatsLink, component: UriStats },
  ]
});

const app = createApp(App);

// Register PrimeVue components globally
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
app.component('InputGroup', InputGroup);
app.component('InputGroupAddon', InputGroupAddon);
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
app.component('PrimeCard', Card);
app.component('PrimeTag', Tag);
app.component('PrimeToolbar', Toolbar);
app.component('ProgressBar', ProgressBar);
app.component('PrimeDivider', Divider);

// Directives
app.directive('tooltip', Tooltip);

// Plugins
app.use(hljsVuePlugin);
app.use(router);
app.use(store);
app.use(PrimeVue, {
    ripple: true,
    theme: {
        preset: LophiidPreset,
        options: {
            darkModeSelector: '.app-dark',
        }
    }
});
app.use(ToastPlugin);
app.use(ConfirmationService);
app.use(CodeMirror, {
  autofocus: true,
  disabled: false,
  indentWithTab: true,
  tabSize: 2,
  placeholder: 'Code goes here...',
  extensions: [],
  theme: 'base16-dark'
});

app.mount('#app');
