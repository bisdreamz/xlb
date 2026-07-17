import { createRouter, createWebHistory } from 'vue-router'
import BackendsPage from './pages/BackendsPage.vue'
import ConnectionsPage from './pages/ConnectionsPage.vue'
import DiagnosticsPage from './pages/DiagnosticsPage.vue'
import EventsPage from './pages/EventsPage.vue'
import OverviewPage from './pages/OverviewPage.vue'

const router = createRouter({
  history: createWebHistory('/admin/'),
  routes: [
    { path: '/', name: 'overview', component: OverviewPage },
    { path: '/backends', name: 'backends', component: BackendsPage },
    { path: '/connections', name: 'connections', component: ConnectionsPage },
    { path: '/events', name: 'events', component: EventsPage },
    { path: '/diagnostics', name: 'diagnostics', component: DiagnosticsPage },
    { path: '/:pathMatch(.*)*', redirect: '/' },
  ],
  scrollBehavior: () => ({ top: 0 }),
})

export default router
