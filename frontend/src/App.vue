<script setup lang="ts">
import Icon from './components/Icon.vue'

const nav = [
  { to: '/', label: '概览', icon: 'overview' as const },
  { to: '/scans', label: '任务列表', icon: 'scans' as const },
  { to: '/cves', label: 'CVE 看板', icon: 'cves' as const },
  { to: '/repos', label: '仓库授权', icon: 'repos' as const },
  { to: '/audit', label: '审计检索', icon: 'audit' as const },
]
</script>

<template>
  <div class="app">
    <aside class="sidebar">
      <div class="brand">
        <div class="brand-mark">CG</div>
        <div>
          <div class="brand-name">CodeGuard</div>
          <div class="brand-sub">Security Console</div>
        </div>
      </div>

      <nav class="nav">
        <div class="nav-group">分析</div>
        <router-link v-for="item in nav.slice(0, 3)" :key="item.to" :to="item.to" class="nav-item">
          <Icon :name="item.icon" />
          {{ item.label }}
        </router-link>

        <div class="nav-group">治理</div>
        <router-link v-for="item in nav.slice(3)" :key="item.to" :to="item.to" class="nav-item">
          <Icon :name="item.icon" />
          {{ item.label }}
        </router-link>
      </nav>

      <div class="sidebar-foot">
        <div>多 Agent 代码安全分析平台</div>
        <div>v0.1.0 · LangGraph · FastAPI</div>
      </div>
    </aside>

    <main class="main">
      <router-view />
    </main>
  </div>
</template>
