<script setup lang="ts">
defineProps<{ name: 'overview' | 'scans' | 'cves' | 'repos' | 'audit' }>()
</script>

<template>
  <svg
    class="icon"
    viewBox="0 0 20 20"
    fill="none"
    stroke="currentColor"
    stroke-width="1.6"
    stroke-linecap="round"
    stroke-linejoin="round"
    aria-hidden="true"
  >
    <template v-if="name === 'overview'">
      <rect x="3" y="3" width="6" height="6" rx="1.4" />
      <rect x="11" y="3" width="6" height="6" rx="1.4" />
      <rect x="3" y="11" width="6" height="6" rx="1.4" />
      <rect x="11" y="11" width="6" height="6" rx="1.4" />
    </template>

    <template v-else-if="name === 'scans'">
      <path d="M6.5 6h10M6.5 10h10M6.5 14h10" />
      <circle cx="3.6" cy="6" r="0.9" fill="currentColor" stroke="none" />
      <circle cx="3.6" cy="10" r="0.9" fill="currentColor" stroke="none" />
      <circle cx="3.6" cy="14" r="0.9" fill="currentColor" stroke="none" />
    </template>

    <template v-else-if="name === 'cves'">
      <path d="M10 2.6 3.6 5.4v4.3c0 3.8 2.7 6.7 6.4 7.7 3.7-1 6.4-3.9 6.4-7.7V5.4L10 2.6Z" />
      <path d="M10 7.2v3.2" />
      <circle cx="10" cy="13.4" r="0.9" fill="currentColor" stroke="none" />
    </template>

    <template v-else-if="name === 'repos'">
      <circle cx="6" cy="4.6" r="1.9" />
      <circle cx="6" cy="15.4" r="1.9" />
      <circle cx="14.4" cy="8" r="1.9" />
      <path d="M6 6.5v6.9" />
      <path d="M14.4 9.9c0 2.2-2 2.9-4.3 3.4" />
    </template>

    <template v-else>
      <path d="M8.2 11.8 11.8 8.2" />
      <path d="M9.6 6.1 11 4.7a2.9 2.9 0 0 1 4.1 4.1l-1.4 1.4" />
      <path d="M10.4 13.9 9 15.3a2.9 2.9 0 0 1-4.1-4.1l1.4-1.4" />
    </template>
  </svg>
</template>

<style scoped>
.icon {
  width: 16px;
  height: 16px;
  flex: 0 0 auto;
  opacity: 0.85;
}
</style>
