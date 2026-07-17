import { expect, test } from '@playwright/test'

test('hosted demo is explicit and never polls a live XLB endpoint', async ({ page }) => {
  const statusRequests: string[] = []
  page.on('request', (request) => {
    if (new URL(request.url()).pathname === '/api/v1/status') statusRequests.push(request.url())
  })

  await page.goto('./')

  await expect(page.getByText('Demo data', { exact: true }).first()).toBeVisible()
  await expect(page.getByText('Interactive demo', { exact: true })).toBeVisible()
  await expect(
    page.getByText('Values are illustrative and do not come from a running XLB instance.'),
  ).toBeVisible()

  await page.waitForTimeout(1_250)
  expect(statusRequests).toEqual([])
})

test('charts remain inside their containers as responsive layouts change', async ({ page }) => {
  const expectChartsToFit = async () => {
    await page.evaluate(
      () =>
        new Promise<void>((resolve) => requestAnimationFrame(() => requestAnimationFrame(() => resolve()))),
    )
    await expect
      .poll(async () => {
        return page.locator('.uplot-chart__host').evaluateAll(
          (hosts) =>
            hosts.filter((host) => {
              const plot = host.querySelector<HTMLElement>('.uplot')
              return (
                plot && Math.abs(plot.getBoundingClientRect().width - host.getBoundingClientRect().width) > 1
              )
            }).length,
        )
      })
      .toBe(0)

    const trendLayout = page.locator('.trend-layout')
    if (await trendLayout.count()) {
      await expect
        .poll(async () => {
          return trendLayout.evaluate((layout) => {
            const bounds = layout.getBoundingClientRect()
            const styles = getComputedStyle(layout)
            const left = bounds.left + Number.parseFloat(styles.paddingLeft)
            const right = bounds.right - Number.parseFloat(styles.paddingRight)
            const singleColumn = styles.gridTemplateColumns.trim().split(/\s+/).length === 1
            return [...layout.children].filter((child) => {
              const panel = child.getBoundingClientRect()
              return singleColumn
                ? Math.abs(panel.left - left) > 1 || Math.abs(panel.right - right) > 1
                : panel.left < left - 1 || panel.right > right + 1
            }).length
          })
        })
        .toBe(0)
    }

    const overflow = await page.evaluate(
      () => document.documentElement.scrollWidth - document.documentElement.clientWidth,
    )
    expect(overflow).toBeLessThanOrEqual(1)
  }

  await page.goto('./')
  await expect(page.locator('.uplot')).toBeVisible()

  for (const width of [1_440, 820, 390, 320]) {
    await page.setViewportSize({ width, height: 844 })
    await expectChartsToFit()
  }

  for (const width of [480, 620, 760, 940, 1_120, 980, 790, 610, 430, 320]) {
    await page.setViewportSize({ width, height: 844 })
  }
  await expectChartsToFit()

  await page.goto('./connections')
  await expect(page.getByRole('button', { name: /Close breakdown.*Coming soon/ })).toBeDisabled()
  await expectChartsToFit()

  await page.goto('./backends')
  for (const width of [1_390, 1_360, 1_281, 1_024, 390]) {
    await page.setViewportSize({ width, height: 844 })
    await expectChartsToFit()
  }
})

test('unfinished features remain empty and explicit in demo mode', async ({ page }) => {
  const errors: Error[] = []
  page.on('pageerror', (error) => errors.push(error))

  await page.goto('./')
  await expect(page.getByText('Lifecycle activity is not collected yet')).toBeVisible()
  await expect(page.getByText('Backend began draining')).toHaveCount(0)

  await page.goto('./connections')
  await expect(page.getByRole('button', { name: /Close breakdown.*Coming soon/ })).toBeDisabled()
  await expect(page.getByText('Passive backend latency is not collected yet')).toBeVisible()
  await expect(page.locator('.close-breakdown')).toHaveCount(0)

  await page.goto('./events')
  await expect(page.getByText('Lifecycle event history is not collected yet')).toBeVisible()
  await expect(page.getByText('Backend discovery synchronized')).toHaveCount(0)

  await page.goto('./backends')
  await expect(page.getByRole('button', { name: /Placement.*Coming soon/ })).toBeDisabled()
  await expect(page.getByRole('button', { name: /Latency p95.*Coming soon/ })).toBeDisabled()
  await expect(page.getByText(/worker-nyc2|nyc2-[abc]/)).toHaveCount(0)
  await expect(page.locator('tbody tr td:nth-child(2)').first()).toHaveText('—')
  await page.locator('tbody tr').first().click()
  const drawer = page.getByRole('dialog')
  await expect(drawer).toBeVisible()
  await expect(drawer.getByText('Demo sample', { exact: true })).toBeVisible()

  await expect(drawer.getByRole('button', { name: /Close breakdown.*Coming soon/ })).toBeDisabled()
  await expect(drawer.getByRole('button', { name: /Latency.*Coming soon/ })).toBeDisabled()
  await expect(drawer.getByText('Passive TCP handshake latency is not collected yet')).toBeVisible()
  await expect(drawer.locator('.latency-detail')).toHaveCount(0)
  await expect(drawer.locator('.close-breakdown')).toHaveCount(0)
  await expect(drawer.locator('.uplot')).toBeVisible()
  await page.evaluate(
    () => new Promise<void>((resolve) => requestAnimationFrame(() => requestAnimationFrame(() => resolve()))),
  )

  expect(errors).toEqual([])
})
