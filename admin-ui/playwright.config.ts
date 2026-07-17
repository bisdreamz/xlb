import { defineConfig } from '@playwright/test'

const livePort = 4175
const demoPort = 4176

export default defineConfig({
  testDir: './tests',
  fullyParallel: true,
  forbidOnly: true,
  retries: 0,
  reporter: 'list',
  use: {
    browserName: 'chromium',
    screenshot: 'only-on-failure',
    trace: 'retain-on-failure',
  },
  projects: [
    {
      name: 'live-console',
      testMatch: 'admin-ui.spec.ts',
      use: { baseURL: `http://127.0.0.1:${livePort}/admin/` },
    },
    {
      name: 'hosted-demo',
      testMatch: 'hosted-demo.spec.ts',
      use: { baseURL: `http://127.0.0.1:${demoPort}/admin/` },
    },
  ],
  webServer: [
    {
      command: `npm run dev -- --host 127.0.0.1 --port ${livePort}`,
      url: `http://127.0.0.1:${livePort}/admin/`,
      reuseExistingServer: true,
      timeout: 30_000,
    },
    {
      command: `npm run dev:demo -- --host 127.0.0.1 --port ${demoPort}`,
      url: `http://127.0.0.1:${demoPort}/admin/`,
      reuseExistingServer: true,
      timeout: 30_000,
    },
  ],
})
