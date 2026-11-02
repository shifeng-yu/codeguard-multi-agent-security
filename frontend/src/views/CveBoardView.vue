<script setup lang="ts">
import type { EChartsOption } from 'echarts'
import { computed, onMounted, ref, watch } from 'vue'
import EChart from '../components/EChart.vue'
import SeverityTag from '../components/SeverityTag.vue'
import { api } from '../api'
import type { PackageRisk, SeverityBucket, TrendPoint } from '../types'

const days = ref(30)
const loading = ref(true)
const error = ref('')

const severity = ref<SeverityBucket[]>([])
const trend = ref<TrendPoint[]>([])
const packages = ref<PackageRisk[]>([])

const SEV_COLOR: Record<string, string> = {
  critical: '#dc2626',
  high: '#ea580c',
  medium: '#ca8a04',
  low: '#64748b',
}

const totalFindings = computed(() => severity.value.reduce((sum, item) => sum + item.count, 0))
const blockedPackages = computed(() => packages.value.reduce((sum, item) => sum + item.blocked, 0))
const cveTotal = computed(() => trend.value.reduce((sum, item) => sum + item.cves, 0))

const severityOption = computed<EChartsOption>(() => ({
  grid: { left: 8, right: 26, top: 10, bottom: 6, containLabel: true },
  tooltip: { trigger: 'axis', axisPointer: { type: 'shadow' } },
  xAxis: {
    type: 'value',
    splitLine: { lineStyle: { color: '#f1f5f9' } },
    axisLabel: { color: '#9ca3af', fontSize: 11 },
  },
  yAxis: {
    type: 'category',
    inverse: true,
    data: severity.value.map((item) => ({ critical: '严重', high: '高危', medium: '中危', low: '低危' })[item.severity]),
    axisLine: { show: false },
    axisTick: { show: false },
    axisLabel: { color: '#4b5563', fontSize: 12 },
  },
  series: [
    {
      type: 'bar',
      barWidth: 14,
      data: severity.value.map((item) => ({
        value: item.count,
        itemStyle: { color: SEV_COLOR[item.severity], borderRadius: [0, 4, 4, 0] },
      })),
      label: { show: true, position: 'right', color: '#4b5563', fontSize: 11 },
    },
  ],
}))

const trendOption = computed<EChartsOption>(() => ({
  grid: { left: 8, right: 12, top: 26, bottom: 4, containLabel: true },
  tooltip: { trigger: 'axis' },
  legend: {
    right: 0,
    top: 0,
    itemWidth: 8,
    itemHeight: 8,
    textStyle: { color: '#4b5563', fontSize: 11 },
  },
  xAxis: {
    type: 'category',
    data: trend.value.map((p) => p.date.slice(5)),
    axisLine: { lineStyle: { color: '#e5e7eb' } },
    axisTick: { show: false },
    axisLabel: { color: '#9ca3af', fontSize: 11 },
  },
  yAxis: {
    type: 'value',
    splitLine: { lineStyle: { color: '#f1f5f9' } },
    axisLabel: { color: '#9ca3af', fontSize: 11 },
  },
  series: [
    {
      name: '命中 CVE',
      type: 'bar',
      stack: 'total',
      barWidth: 8,
      data: trend.value.map((p) => p.cves),
      itemStyle: { color: '#f97316', borderRadius: [3, 3, 0, 0] },
    },
    {
      name: '扫描数',
      type: 'line',
      smooth: true,
      symbol: 'none',
      data: trend.value.map((p) => p.scans),
      lineStyle: { width: 2, color: '#2563eb' },
    },
  ],
}))

async function load() {
  loading.value = true
  error.value = ''
  try {
    const [severityData, trendData, packageData] = await Promise.all([
      api.severity(days.value),
      api.trend(days.value),
      api.topPackages(days.value, 12),
    ])
    severity.value = severityData.items
    trend.value = trendData.items
    packages.value = packageData.items
  } catch (err) {
    error.value = err instanceof Error ? err.message : String(err)
  } finally {
    loading.value = false
  }
}

watch(days, load)
onMounted(load)
</script>

<template>
  <div class="page-head">
    <div>
      <h1 class="page-title">CVE 看板</h1>
      <p class="page-desc">按严重级、时间与依赖包聚合，数据直接来自扫描写入的 findings 表</p>
    </div>
    <div class="toolbar">
      <select v-model.number="days" class="select">
        <option :value="7">近 7 天</option>
        <option :value="30">近 30 天</option>
        <option :value="90">近 90 天</option>
      </select>
      <button class="btn" :disabled="loading" @click="load"><span v-if="loading" class="spinner" />刷新</button>
    </div>
  </div>

  <div v-if="error" class="error-box" style="margin-bottom: 14px">{{ error }}</div>

  <div class="grid grid-4" style="margin-bottom: 16px">
    <div class="card kpi">
      <div class="kpi-label">发现项合计</div>
      <div class="kpi-value">{{ totalFindings }}</div>
      <div class="kpi-foot">近 {{ days }} 天所有扫描</div>
    </div>
    <div class="card kpi">
      <div class="kpi-label">命中 CVE</div>
      <div class="kpi-value">{{ cveTotal }}</div>
      <div class="kpi-foot">按扫描日累加</div>
    </div>
    <div class="card kpi">
      <div class="kpi-label">阻断项</div>
      <div class="kpi-value" style="color: var(--danger)">{{ blockedPackages }}</div>
      <div class="kpi-foot">Top 包维度阻断计数</div>
    </div>
    <div class="card kpi">
      <div class="kpi-label">严重级最高</div>
      <div class="kpi-value" style="font-size: 17px; font-family: inherit">
        <SeverityTag :severity="severity.find((s) => s.count > 0)?.severity ?? 'low'" />
      </div>
      <div class="kpi-foot">当前窗口内存在的最严重级别</div>
    </div>
  </div>

  <div class="grid grid-2" style="margin-bottom: 16px">
    <div class="card">
      <div class="card-head"><h2 class="card-title">严重级分布</h2></div>
      <div class="card-body">
        <EChart :option="severityOption" height="240px" />
      </div>
    </div>
    <div class="card">
      <div class="card-head"><h2 class="card-title">CVE 命中趋势</h2></div>
      <div class="card-body">
        <EChart :option="trendOption" height="240px" />
      </div>
    </div>
  </div>

  <div class="card">
    <div class="card-head">
      <h2 class="card-title">高风险依赖包</h2>
      <span class="dim" style="font-size: 12px">按阻断项 → 严重级 → 发现数排序</span>
    </div>
    <div class="table-wrap">
      <table class="table">
        <thead>
          <tr>
            <th style="width: 44px">#</th>
            <th>包名</th>
            <th>最高严重级</th>
            <th>发现数</th>
            <th>阻断数</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="(pkg, index) in packages" :key="pkg.package_name">
            <td class="num dim">{{ index + 1 }}</td>
            <td class="mono">{{ pkg.package_name }}</td>
            <td><SeverityTag :severity="pkg.severity" /></td>
            <td class="num">{{ pkg.findings }}</td>
            <td class="num" :style="{ color: pkg.blocked ? 'var(--danger)' : 'var(--ink-2)' }">{{ pkg.blocked }}</td>
          </tr>
          <tr v-if="!packages.length && !loading">
            <td colspan="5" class="empty"><strong>暂无依赖风险</strong>扫描含 requirements.txt 的仓库后会有数据</td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>
</template>
