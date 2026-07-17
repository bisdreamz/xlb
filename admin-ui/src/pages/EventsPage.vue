<script setup lang="ts">
import ComingSoon from '../components/ComingSoon.vue'
</script>

<template>
  <section class="route-hero page-shell">
    <div>
      <p class="eyebrow-label"><i></i> Events</p>
      <h1>What changed, and when.</h1>
      <p>
        Backend lifecycle, discovery, and runtime transitions belong here—not scattered across unrelated
        graphs.
      </p>
    </div>
    <div class="route-hero__facts">
      <div><span>Retained locally</span><strong>Coming soon</strong></div>
      <div><span>Durable export</span><strong>Coming soon</strong></div>
    </div>
  </section>

  <section class="events-notice page-shell">
    <strong>Planned lifecycle API</strong
    ><span
      >This page is the reviewed UI shape. Event collection, the bounded userspace ring, and OpenTelemetry log
      export will land on their own branch.</span
    >
  </section>

  <section class="events-layout page-shell">
    <aside class="event-summary">
      <span class="section-index">Latest window</span>
      <div><small>Backend transitions</small><strong>—</strong></div>
      <div><small>Discovery changes</small><strong>—</strong></div>
      <div><small>Runtime changes</small><strong>—</strong></div>
      <p>
        Watcher initialization will establish a baseline without emitting a false burst of “backend added”
        events.
      </p>
    </aside>

    <article class="event-feed panel">
      <header class="panel-head">
        <div>
          <span class="section-index">Event timeline</span>
          <h2>Local instance activity</h2>
          <p>Newest first. Durable search and fleet correlation remain in your observability platform.</p>
        </div>
      </header>
      <ComingSoon
        title="Lifecycle event history is not collected yet"
        description="This timeline will remain empty until the bounded event ring, status API, and OpenTelemetry log export land. No events are simulated in demo mode."
      />
    </article>
  </section>
</template>
