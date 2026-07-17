import { expect, test } from '@playwright/test'
import { demoStatus } from '../src/data/demo-status'

test.beforeEach(async ({ page }) => {
  await page.route('**/api/v1/status', (route) =>
    route.fulfill({
      json: { ...demoStatus, sampled_at_unix_ms: Date.now(), sample_age_ms: 0 },
    }),
  )
})

test('primary routes preserve the local-instance information hierarchy', async ({ page }) => {
  await page.goto('./')
  await expect(page.getByRole('heading', { name: 'openrtb-edge / eth0' })).toBeVisible()
  await expect(page.locator('.sample-indicator').getByText('Live', { exact: true })).toBeVisible()
  await expect(page.getByText('Backend pool', { exact: true })).toBeVisible()

  const routes = [
    ['Backends', 'Where this instance sends traffic.'],
    ['Connections', 'How traffic sessions behave.'],
    ['Events', 'What changed, and when.'],
    ['Diagnostics', 'Why traffic might not be routed.'],
  ] as const

  for (const [link, heading] of routes) {
    await page
      .getByRole('navigation', { name: 'Console sections' })
      .getByRole('link', { name: new RegExp(`^${link}`) })
      .click()
    await expect(page.getByRole('heading', { name: heading })).toBeVisible()
  }
})

test('backend pool supports pagination, filtering, sorting, and drill-down', async ({ page }) => {
  await page.goto('./backends')
  await expect(page.getByText('Showing 1–10 of 12 backends')).toBeVisible()

  await page.getByRole('button', { name: 'Next page' }).click()
  await expect(page.getByText('Page 2 / 2')).toBeVisible()
  await page.getByRole('button', { name: 'Previous page' }).click()

  await page
    .getByRole('columnheader')
    .getByRole('button', { name: /Backend/ })
    .click()
  await page
    .getByRole('columnheader')
    .getByRole('button', { name: /Backend/ })
    .click()
  await expect(page.locator('tbody tr').first()).toContainText('bidder-api-7f8797d8f4-x3j5k')
  await expect(page.getByRole('button', { name: /Placement.*Coming soon/ })).toBeDisabled()
  await expect(page.locator('tbody tr td:nth-child(2)').first()).toHaveText('—')
  await page.locator('tbody tr').first().click()
  const drawer = page.getByRole('dialog')
  await expect(drawer).toBeVisible()
  await expect(page.getByRole('button', { name: 'Close backend details' })).toBeFocused()
  await expect(page.getByRole('button', { name: 'Close backend details' })).toBeVisible()
  await expect(drawer.getByRole('button', { name: /Close breakdown.*Coming soon/ })).toBeDisabled()
  await expect(drawer.getByRole('button', { name: /Latency.*Coming soon/ })).toBeDisabled()
  await expect(drawer.getByText('Client ended connection')).toHaveCount(0)
  await page.getByRole('button', { name: 'Close backend details' }).click()

  await page.getByRole('searchbox', { name: 'Search backends' }).fill('does-not-exist')
  await expect(page.getByText('No backends match these filters.')).toBeVisible()
})

test('backend drawer is keyboard-contained and preserves unrelated URL state', async ({ page }) => {
  await page.goto('./backends?view=compact')
  const details = page.getByRole('button', { name: /Open details for/ }).first()
  await details.focus()
  await details.press('Enter')

  const drawer = page.getByRole('dialog')
  await expect(drawer).toBeVisible()
  await expect(page).toHaveURL(/view=compact/)
  await expect(page).toHaveURL(/backend=/)
  await page.keyboard.press('Escape')
  await expect(drawer).toHaveCount(0)
  await expect(details).toBeFocused()
  await expect(page).toHaveURL(/view=compact/)
  await expect(page).not.toHaveURL(/backend=/)
})

test('missing resource signals remain unavailable rather than becoming zero', async ({ page }) => {
  await page.unroute('**/api/v1/status')
  await page.route('**/api/v1/status', (route) =>
    route.fulfill({
      json: {
        ...demoStatus,
        sampled_at_unix_ms: Date.now(),
        sample_age_ms: 0,
        resources: {
          cpu_percent: null,
          host_cpu_percent: null,
          process_cpu_percent: null,
          network_percent: null,
          flow_map_percent: null,
          overall_percent: null,
        },
      },
    }),
  )

  await page.goto('./')
  const resourceCard = page.locator('.metric-card').filter({ hasText: 'Resource pressure' })
  await expect(resourceCard.getByText('Unavailable', { exact: true })).toBeVisible()
  await expect(page.getByText('Unavailable until every capacity signal is reported')).toBeVisible()
  await expect(page.getByText('Capacity headroom').locator('..').getByText('—')).toBeVisible()

  await page.getByRole('link', { name: /^Diagnostics/ }).click()
  await expect(
    page.locator('.route-hero__facts div').filter({ hasText: 'Overall pressure' }).getByText('Unavailable'),
  ).toBeVisible()
  await expect(page.locator('.uplot-chart__legend strong')).toHaveText(['—', '—', '—', '—'])
})

test('pagination clamps when the live backend pool shrinks', async ({ page }) => {
  await page.unroute('**/api/v1/status')
  let requests = 0
  await page.route('**/api/v1/status', (route) => {
    requests += 1
    const backends = requests === 1 ? demoStatus.backends : demoStatus.backends.slice(0, 5)
    return route.fulfill({
      json: {
        ...demoStatus,
        sampled_at_unix_ms: Date.now(),
        sample_age_ms: 0,
        provider: {
          ...demoStatus.provider,
          discovered_backends: backends.length,
          routable_backends: backends.length,
        },
        backends,
      },
    })
  })

  await page.goto('./backends')
  await page.getByRole('button', { name: 'Next page' }).click()
  await expect(page.getByText('Page 2 / 2')).toBeVisible()
  await expect(page.getByText('Showing 1–5 of 5 backends')).toBeVisible({ timeout: 2_500 })
  await expect(page.getByText('Page 1 / 1')).toBeVisible()
})

test('connection lifecycle disables unavailable close attribution', async ({ page }) => {
  await page.goto('./connections')
  await expect(page.getByText('Opened and closed volume share one scale.')).toBeVisible()
  await expect(page.getByRole('button', { name: /Close breakdown.*Coming soon/ })).toBeDisabled()
  await expect(page.getByText('Client ended connection')).toHaveCount(0)
})

test('mobile layout retains every route and avoids horizontal page overflow', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 })
  await page.goto('./')

  const navigation = page.getByRole('navigation', { name: 'Console sections' })
  await expect(navigation).toBeVisible()
  await expect(navigation.getByRole('link', { name: 'Diagnostics' })).toBeAttached()
  const overflow = await page.evaluate(
    () => document.documentElement.scrollWidth - document.documentElement.clientWidth,
  )
  expect(overflow).toBeLessThanOrEqual(1)
})

test('theme choice persists across navigation and reload', async ({ page }) => {
  await page.goto('./')
  await page.getByRole('button', { name: 'Use dark theme' }).click()
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark')
  await page.getByRole('link', { name: /^Backends/ }).click()
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark')
  await page.reload()
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark')
})

test('a slow status response is allowed to complete', async ({ page }) => {
  await page.unroute('**/api/v1/status')
  let requests = 0
  await page.route('**/api/v1/status', async (route) => {
    requests += 1
    await new Promise((resolve) => setTimeout(resolve, 1_250))
    await route.fulfill({
      json: { ...demoStatus, sampled_at_unix_ms: Date.now(), sample_age_ms: 0 },
    })
  })

  await page.goto('./')
  await expect(page.locator('.sample-indicator').getByText('Live', { exact: true })).toBeVisible({
    timeout: 2_500,
  })
  await expect(page.getByRole('heading', { name: 'openrtb-edge / eth0' })).toBeVisible()
  expect(requests).toBe(1)
})

test('a hung status response makes previously live data stale', async ({ page }) => {
  await page.unroute('**/api/v1/status')
  let requests = 0
  await page.route('**/api/v1/status', async (route) => {
    requests += 1
    if (requests === 1) {
      await route.fulfill({
        json: { ...demoStatus, sampled_at_unix_ms: Date.now(), sample_age_ms: 0 },
      })
      return
    }
    await new Promise(() => {})
  })

  await page.goto('./')
  await expect(page.locator('.sample-indicator').getByText('Live', { exact: true })).toBeVisible()
  await expect(page.locator('.sample-indicator').getByText('Stale', { exact: true })).toBeVisible({
    timeout: 7_000,
  })
  await expect(
    page.getByText('Showing the last successful snapshot while the console reconnects.'),
  ).toBeVisible()
})

test('failed initial status load never substitutes demo measurements', async ({ page }) => {
  await page.unroute('**/api/v1/status')
  await page.route('**/api/v1/status', (route) =>
    route.fulfill({ status: 503, contentType: 'text/plain', body: 'status unavailable' }),
  )

  await page.goto('./')
  await expect(page.getByText('Disconnected', { exact: true })).toBeVisible()
  await expect(page.getByRole('heading', { name: 'Unable to reach this XLB instance.' })).toBeVisible()
  await expect(page.getByText('openrtb-edge')).toHaveCount(0)
})

test('a lost API marks the last real snapshot stale instead of replacing it', async ({ page }) => {
  await page.unroute('**/api/v1/status')
  let requests = 0
  await page.route('**/api/v1/status', (route) => {
    requests += 1
    if (requests === 1) {
      return route.fulfill({
        json: { ...demoStatus, sampled_at_unix_ms: Date.now(), sample_age_ms: 0 },
      })
    }
    return route.fulfill({ status: 503, contentType: 'text/plain', body: 'status unavailable' })
  })

  await page.goto('./')
  await expect(page.locator('.sample-indicator').getByText('Live', { exact: true })).toBeVisible()
  await expect(page.locator('.sample-indicator').getByText('Stale', { exact: true })).toBeVisible({
    timeout: 3_000,
  })
  await expect(page.getByRole('heading', { name: 'openrtb-edge / eth0' })).toBeVisible()
  await expect(
    page.getByText('Showing the last successful snapshot while the console reconnects.'),
  ).toBeVisible()
})
