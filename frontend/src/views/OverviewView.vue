<script setup lang="ts">
import type { EChartsOption } from 'echarts'
import { computed, onMounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import EChart from '../components/EChart.vue'
import SeverityTag from '../components/SeverityTag.vue'
import StatusBadge from '../components/StatusBadge.vue'
import { api } from '../api'
import { fmtDuration, fmtTimeShort } from '../format'
import type { DashboardSummary, PackageRisk, ScanItem, SeverityBucket, TrendPoint } from '../types'

const router = useRouter()
const loading = ref(true)
const error = ref('')

const summary = ref<DashboardSummary | null>(null)
const trend = ref<TrendPoint[]>([])
const severity = ref<SeverityBucket[]>([])
const packages = ref<PackageRisk[]>([])
const recent = ref<ScanItem[]>([])

const SEV_COLOR: Record<string, string> = {
  critical: '#dc2626',
  high: '#ea580c',
  medium: '#ca8a04',
  low: '#64748b',
}

const trendOption = computed<EChartsOption>(() => ({
  grid: { left: 8, right: 12, top: 28, bottom: 4, containLabel: true },
  tooltip: { trigger: 'axis', axisPointer: { type: 'shadow' } },
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
      name: '扫描数',
      type: 'line',
      smooth: true,
      symbol: 'none',
      data: trend.value.map((p) => p.scans),
      lineStyle: { width: 2, color: '#2563eb' },
      areaStyle: {
        color: {
          type: 'linear',
          x: 0,
          y: 0,
          x2: 0,
          y2: 1,
          colorStops: [
            { offset: 0, color: 'rgba(37,99,235,0.22)' },
            { offset: 1, color: 'rgba(37,99,235,0.01)' },
          ],
        },
      },
    },
    {
      name: '阻断数',
      type: 'bar',
      barWidth: 7,
      data: trend.value.map((p) => p.blocked),
      itemStyle: { color: '#dc2626', borderRadius: [3, 3, 0, 0] },
    },
  ],
}))

const severityOption = computed<EChartsOption>(() => ({
  tooltip: { trigger: 'item', formatter: '{b}: {c} ({d}%)' },
  legend: {
    bottom: 0,
    itemWidth: 8,
    itemHeight: 8,
    textStyle: { color: '#4b5563', fontSize: 11 },
  },
  series: [
    {
      type: 'pie',
      radius: ['56%', '76%'],
      center: ['50%', '44%'],
      avoidLabelOverlap: true,
      label: { show: false },
      itemStyle: { borderColor: '#fff', borderWidth: 2 },
      data: severity.value
        .filter((item) => item.count > 0)
        .map((item) => ({
          name: { critical: '严重', high: '高危', medium: '中危', low: '低危' }[item.severity],
          value: item.count,
          itemStyle: { color: SEV_COLOR[item.severity] },
        })),
    },
  ],
}))

const hasSeverity = computed(() => severity.value.some((item) => item.count > 0))

async function load() {
  loading.value = true
  error.value = ''
  try {
    const [summaryData, trendData, severityData, packageData, scansData] = await Promise.all([
      api.summary(1),
      api.trend(30),
      api.severity(30),
      api.topPackages(30, 6),
      api.listScans({ page_size: 6 }),
    ])
    summary.value = summaryData
    trend.value = trendData.items
    severity.value = severityData.items
    packages.value = packageData.items
    recent.value = scansData.items
  } catch (err) {
    error.value = err instanceof Error ? err.message : String(err)
  } finally {
    loading.value = false
  }
}

onMounted(load)
</script>

<template>
  <div class="page-head">
    <div>
      <h1 class="page-title">概览</h1>
      <p class="page-desc">最近 24 小时的安全闸门状态与近 30 天趋势</p>
    </div>
    <button class="btn" :disabled="loading" @click="load">
      <span v-if="loading" class="spinner" />刷新
    </button>
  </div>

  <div v-if="error" class="error-box" style="margin-bottom: 16px">
    数据加载失败：{{ error }}。请确认后端已启动（127.0.0.1:8000）。
  </div>

  <div class="grid grid-4" style="margin-bottom: 16px">
    <div class="card kpi">
      <div class="kpi-label">今日扫描</div>
      <div class="kpi-value">{{ summary?.scans ?? 0 }}</div>
      <div class="kpi-foot">已授权仓库 {{ summary?.repos ?? 0 }} 个</div>
    </div>
    <div class="card kpi">
      <div class="kpi-label">阻断 PR</div>
      <div class="kpi-value" style="color: var(--danger)">{{ summary?.blocked ?? 0 }}</div>
      <div class="kpi-foot">阻断项合计 {{ summary?.blockers ?? 0 }}</div>
    </div>
    <div class="card kpi">
      <div class="kpi-label">命中 CVE</div>
      <div class="kpi-value">{{ summary?.cves ?? 0 }}</div>
      <div class="kpi-foot">含传递依赖</div>
    </div>
    <div class="card kpi">
      <div class="kpi-label">平均扫描耗时</div>
      <div class="kpi-value">{{ fmtDuration(summary?.avg_duration_ms ?? null) }}</div>
      <div class="kpi-foot">缓存命中后为毫秒级</div>
    </div>
  </div>

  <div class="grid grid-3-2" style="margin-bottom: 16px">
    <div class="card">
      <div class="card-head">
        <h2 class="card-title">扫描与阻断趋势 · 30 天</h2>
        <span class="dim" style="font-size: 12px">按天聚合</span>
      </div>
      <div class="card-body">
        <EChart v-if="trend.length" :option="trendOption" height="282px" />
        <div v-else class="empty"><strong>暂无数据</strong>跑一次扫描后这里会出曲线</div>
      </div>
    </div>

    <div class="card">
      <div class="card-head">
        <h2 class="card-title">漏洞严重级分布</h2>
        <span class="dim" style="font-size: 12px">近 30 天</span>
      </div>
      <div class="card-body">
        <EChart v-if="hasSeverity" :option="severityOption" height="282px" />
        <div v-else class="empty"><strong>暂无发现项</strong>当前窗口内没有漏洞记录</div>
      </div>
    </div>
  </div>

  <div class="grid grid-3-2">
    <div class="card">
      <div class="card-head">
        <h2 class="card-title">最近扫描</h2>
        <span class="link" style="font-size: 12px" @click="router.push('/scans')">查看全部 →</span>
      </div>
      <div class="table-wrap">
        <table class="table">
          <thead>
            <tr>
              <th>仓库</th>
              <th>PR</th>
              <th>结论</th>
              <th>CVE</th>
              <th>耗时</th>
              <th>时间</th>
            </tr>
          </thead>
          <tbody>
            <tr
              v-for="scan in recent"
              :key="scan.scan_id"
              class="row-link"
              @click="router.push(`/scans/${scan.scan_id}`)"
            >
              <td class="mono">{{ scan.repo || '—' }}</td>
              <td class="num">#{{ scan.pr_number ?? '—' }}</td>
              <td><StatusBadge :status="scan.status" :verdict="scan.verdict" /></td>
              <td class="num">{{ scan.cve_count }}</td>
              <td class="num">{{ fmtDuration(scan.duration_ms) }}</td>
              <td class="dim nowrap">{{ fmtTimeShort(scan.started_at) }}</td>
            </tr>
            <tr v-if="!recent.length">
              <td colspan="6" class="empty">还没有扫描记录，先到「任务列表」发起一次</td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>

    <div class="card">
      <div class="card-head">
        <h2 class="card-title">高风险依赖 Top 6</h2>
        <span class="dim" style="font-size: 12px">按阻断项排序</span>
      </div>
      <div class="card-body" style="padding-top: 6px">
        <div v-for="pkg in packages" :key="pkg.package_name" class="pkg-row">
          <div class="pkg-main">
            <span class="mono">{{ pkg.package_name }}</span>
            <SeverityTag :severity="pkg.severity" />
          </div>
          <div class="pkg-meta">
            <span>{{ pkg.findings }} 项发现</span>
            <span class="dim">·</span>
            <span style="color: var(--danger)">{{ pkg.blocked }} 项阻断</span>
          </div>
        </div>
        <div v-if="!packages.length" class="empty"><strong>暂无依赖风险</strong>扫描结果会按包名聚合到这里</div>
      </div>
    </div>
  </div>
</template>

<style scoped>
.pkg-row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  padding: 10px 0;
  border-bottom: 1px solid #f1f2f4;
}

.pkg-row:last-child {
  border-bottom: none;
}

.pkg-main {
  display: flex;
  align-items: center;
  gap: 8px;
  min-width: 0;
}

.pkg-meta {
  display: flex;
  align-items: center;
  gap: 5px;
  font-size: 12px;
  color: var(--ink-2);
  white-space: nowrap;
}
</style>
