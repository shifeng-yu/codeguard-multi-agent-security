import { createRouter, createWebHistory } from 'vue-router'

const router = createRouter({
  history: createWebHistory(),
  routes: [
    {
      path: '/',
      name: 'overview',
      component: () => import('./views/OverviewView.vue'),
      meta: { title: '概览' },
    },
    {
      path: '/repos',
      name: 'repos',
      component: () => import('./views/ReposView.vue'),
      meta: { title: '仓库授权' },
    },
    {
      path: '/scans',
      name: 'scans',
      component: () => import('./views/ScansView.vue'),
      meta: { title: '任务列表' },
    },
    {
      path: '/scans/:id',
      name: 'scan-detail',
      component: () => import('./views/ScanDetailView.vue'),
      meta: { title: '任务详情' },
    },
    {
      path: '/cves',
      name: 'cves',
      component: () => import('./views/CveBoardView.vue'),
      meta: { title: 'CVE 看板' },
    },
    {
      path: '/audit',
      name: 'audit',
      component: () => import('./views/AuditView.vue'),
      meta: { title: '审计检索' },
    },
  ],
})

router.afterEach((to) => {
  const title = (to.meta.title as string) || ''
  document.title = title ? `${title} · CodeGuard` : 'CodeGuard'
})

export default router
