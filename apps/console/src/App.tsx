import { useCallback, useEffect, useState } from 'react';
import {
  AppBar,
  Box,
  Button,
  Card,
  CardContent,
  Chip,
  Container,
  CssBaseline,
  Stack,
  Tab,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableRow,
  Tabs,
  ThemeProvider,
  Toolbar,
  Typography,
  createTheme,
} from '@mui/material';
import { beginLogin, completeLogin } from './auth';
import {
  api,
  type Agent,
  type AuditEvent,
  type Approval,
  type Overview,
  type Session,
} from './api';
import { Approvals } from './Approvals';

const theme = createTheme({
  palette: { mode: 'light', primary: { main: '#1f3a5f' } },
  typography: { fontFamily: 'system-ui, -apple-system, sans-serif' },
});

/** prd.md §10: production and sandbox must remain visually distinct, so nobody
 *  resolves a production approval believing they are in sandbox. */
function EnvironmentBanner({ name }: { name: string }) {
  const isProduction = name.toLowerCase().includes('production');
  return (
    <Box
      sx={{
        bgcolor: isProduction ? '#7f1d1d' : '#1e3a2f',
        color: 'white',
        px: 2,
        py: 0.5,
        fontSize: 13,
        letterSpacing: 0.5,
      }}
    >
      {isProduction ? 'PRODUCTION — actions here are enforced and irreversible' : 'SANDBOX'}
    </Box>
  );
}

function StatCard({
  label,
  value,
  alarming,
}: {
  label: string;
  value: string;
  alarming?: boolean;
}) {
  return (
    <Card variant="outlined" sx={{ minWidth: 140, flex: 1 }}>
      <CardContent>
        <Typography
          variant="h4"
          color={alarming && Number(value) > 0 ? 'error.main' : 'text.primary'}
        >
          {value}
        </Typography>
        <Typography variant="body2" color="text.secondary">
          {label}
        </Typography>
      </CardContent>
    </Card>
  );
}

export function App() {
  const [token, setToken] = useState<string | null>(null);
  const [session, setSession] = useState<Session | null>(null);
  const [tab, setTab] = useState(0);
  const [overview, setOverview] = useState<Overview | null>(null);
  const [approvals, setApprovals] = useState<Approval[]>([]);
  const [agents, setAgents] = useState<Agent[]>([]);
  const [audit, setAudit] = useState<AuditEvent[]>([]);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    void completeLogin().then((t) => {
      if (t) setToken(t);
    });
  }, []);

  const refresh = useCallback(async () => {
    if (!token) return;
    try {
      const s = await api<Session>(token, '/v1/session');
      setSession(s);
      // Approvals are polled rather than pushed: a webhook or SSE message is a hint
      // to refresh, never authority in itself (architecture.md §11).
      setApprovals((await api<{ approvals: Approval[] }>(token, '/v1/approvals')).approvals);
      // Role-gated endpoints: an approver legitimately cannot read these.
      await Promise.all([
        api<Overview>(token, '/v1/overview')
          .then(setOverview)
          .catch(() => setOverview(null)),
        api<{ agents: Agent[] }>(token, '/v1/agents')
          .then((r) => setAgents(r.agents))
          .catch(() => setAgents([])),
        api<{ events: AuditEvent[] }>(token, '/v1/audit-events?limit=25')
          .then((r) => setAudit(r.events))
          .catch(() => setAudit([])),
      ]);
      setError(null);
    } catch (e) {
      setError(String(e));
    }
  }, [token]);

  useEffect(() => {
    void refresh();
    const timer = setInterval(() => void refresh(), 5000);
    return () => clearInterval(timer);
  }, [refresh]);

  if (!token) {
    return (
      <ThemeProvider theme={theme}>
        <CssBaseline />
        <Container maxWidth="sm" sx={{ mt: 12, textAlign: 'center' }}>
          <Typography variant="h4" gutterBottom>
            TrustOS
          </Typography>
          <Typography color="text.secondary" gutterBottom>
            Control layer for AI agent actions
          </Typography>
          <Button variant="contained" size="large" sx={{ mt: 3 }} onClick={() => void beginLogin()}>
            Sign in
          </Button>
        </Container>
      </ThemeProvider>
    );
  }

  return (
    <ThemeProvider theme={theme}>
      <CssBaseline />
      <EnvironmentBanner name={session?.organization.name ?? ''} />
      <AppBar position="static" color="default" elevation={0}>
        <Toolbar>
          <Typography variant="h6" sx={{ flexGrow: 1 }}>
            TrustOS
          </Typography>
          {session ? (
            <Stack direction="row" spacing={1} sx={{ alignItems: 'center' }}>
              <Typography variant="body2">{session.organization.name}</Typography>
              <Chip size="small" label={session.role} />
              <Typography variant="body2" color="text.secondary">
                {session.user_id}
              </Typography>
            </Stack>
          ) : null}
        </Toolbar>
      </AppBar>

      <Container maxWidth="lg" sx={{ py: 3 }}>
        {error ? <Typography color="error">{error}</Typography> : null}

        <Tabs value={tab} onChange={(_e, v: number) => setTab(v)} sx={{ mb: 3 }}>
          <Tab label={`Approvals${approvals.length ? ` (${approvals.length})` : ''}`} />
          <Tab label="Overview" />
          <Tab label="Agents" />
          <Tab label="Audit" />
        </Tabs>

        {tab === 0 ? (
          <Approvals token={token} approvals={approvals} onChanged={() => void refresh()} />
        ) : null}

        {tab === 1 ? (
          overview ? (
            <Stack direction="row" spacing={2} sx={{ flexWrap: 'wrap', gap: 2 }}>
              <StatCard label="Evaluated" value={overview.evaluated} />
              <StatCard label="Denied" value={overview.denied} />
              <StatCard label="Pending approvals" value={overview.pending_approvals} />
              <StatCard label="Grants consumed" value={overview.consumed_grants} />
              <StatCard label="Succeeded" value={overview.succeeded} />
              {/* Never folded into succeeded: a consumed grant with no report is
                  visibly unknown, not a quiet success (AUT-04). */}
              <StatCard label="Missing outcomes" value={overview.missing_outcomes} alarming />
            </Stack>
          ) : (
            <Typography color="text.secondary">Your role cannot read the overview.</Typography>
          )
        ) : null}

        {tab === 2 ? (
          <Table size="small">
            <TableHead>
              <TableRow>
                <TableCell>Agent</TableCell>
                <TableCell>Status</TableCell>
                <TableCell>Owner</TableCell>
                <TableCell align="right">Capabilities</TableCell>
                <TableCell align="right">Epoch</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {agents.map((a) => (
                <TableRow key={a.id}>
                  <TableCell>{a.name}</TableCell>
                  <TableCell>
                    <Chip
                      size="small"
                      label={a.status}
                      color={
                        a.status === 'active'
                          ? 'success'
                          : a.status === 'revoked'
                            ? 'error'
                            : 'default'
                      }
                    />
                  </TableCell>
                  <TableCell>{a.owner ?? <em>none</em>}</TableCell>
                  <TableCell align="right">{a.capabilities}</TableCell>
                  <TableCell align="right">{a.auth_epoch}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        ) : null}

        {tab === 3 ? (
          <Table size="small">
            <TableHead>
              <TableRow>
                <TableCell align="right">#</TableCell>
                <TableCell>Event</TableCell>
                <TableCell>Actor</TableCell>
                <TableCell>When</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {audit.map((e) => (
                <TableRow key={e.id}>
                  <TableCell align="right" sx={{ fontFamily: 'monospace' }}>
                    {e.sequence}
                  </TableCell>
                  <TableCell sx={{ fontFamily: 'monospace' }}>{e.event_type}</TableCell>
                  <TableCell>{e.actor_type}</TableCell>
                  <TableCell>{new Date(e.occurred_at).toLocaleTimeString()}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        ) : null}
      </Container>
    </ThemeProvider>
  );
}
