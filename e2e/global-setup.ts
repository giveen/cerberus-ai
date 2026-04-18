import { execSync } from 'node:child_process';
import path from 'node:path';

const DASHBOARD_URL = 'http://127.0.0.1:8000';
const STARTUP_TIMEOUT_MS = 180_000;
const POLL_INTERVAL_MS = 2_000;

function runDockerCommand(command: string, cwd: string): string {
  return execSync(command, {
    cwd,
    stdio: ['ignore', 'pipe', 'pipe'],
    encoding: 'utf-8',
  }).trim();
}

async function waitForDashboard(url: string, dockerDir: string): Promise<void> {
  const deadline = Date.now() + STARTUP_TIMEOUT_MS;

  while (Date.now() < deadline) {
    try {
      const health = runDockerCommand(
        'docker inspect --format "{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}" cerberus-dashboard',
        dockerDir
      );

      if (health === 'healthy' || health === 'running') {
        const response = await fetch(url, { method: 'GET' });
        if (response.ok) {
          return;
        }
      }
    } catch {
      // Services may still be starting; continue polling.
    }

    await new Promise((resolve) => setTimeout(resolve, POLL_INTERVAL_MS));
  }

  throw new Error(
    `Timed out waiting for Docker dashboard at ${url}. Ensure docker compose services are healthy.`
  );
}

export default async function globalSetup(): Promise<void> {
  if (process.env.PLAYWRIGHT_LOCAL_SERVER) {
    return;
  }

  const workspaceRoot = path.resolve(__dirname, '..');
  const dockerDir = path.join(workspaceRoot, 'dockerized');

  console.log('[playwright] Building and starting dockerized dashboard stack...');
  runDockerCommand('docker compose build', dockerDir);
  runDockerCommand('docker compose up -d', dockerDir);

  console.log('[playwright] Waiting for dashboard health...');
  await waitForDashboard(DASHBOARD_URL, dockerDir);
}
