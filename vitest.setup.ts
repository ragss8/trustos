/**
 * Loads .env for test runs so suites hit the same database and identity provider the
 * application does, rather than a hardcoded fallback that can silently drift from it.
 *
 * Node's built-in loader: no dotenv dependency. Missing .env is not fatal — CI injects
 * these as real environment variables instead.
 */
try {
  process.loadEnvFile('.env');
} catch {
  // No .env (CI, or a fresh clone before `cp .env.example .env`). Suites fall back to
  // their documented defaults, and the connection error names what is missing.
}
