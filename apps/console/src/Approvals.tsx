import { useState } from 'react';
import {
  Alert,
  Box,
  Button,
  Card,
  CardContent,
  Chip,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  Stack,
  TextField,
  Typography,
} from '@mui/material';
import { api, ApiError, type Approval } from './api';

/**
 * The approval queue (prd.md §10).
 *
 * Three requirements shape this screen and are easy to break by accident:
 *
 *   - NEVER preselect approval. Approve and Reject get equal visual weight; there is
 *     no default action and no primary-button nudge toward yes.
 *   - No optimistic UI. The row updates only after the server confirms, because the
 *     server may refuse on separation of duties or a resolution race, and showing
 *     "approved" before that would be a lie the operator acts on.
 *   - Works at phone width, since approvals are the one thing people resolve on a
 *     phone.
 */

function expiresIn(iso: string): string {
  const ms = new Date(iso).getTime() - Date.now();
  if (ms <= 0) return 'expired';
  const minutes = Math.floor(ms / 60000);
  return minutes >= 1 ? `${minutes}m left` : `${Math.floor(ms / 1000)}s left`;
}

export function Approvals({
  token,
  approvals,
  onChanged,
}: {
  token: string;
  approvals: Approval[];
  onChanged: () => void;
}) {
  const [pending, setPending] = useState<{
    approval: Approval;
    effect: 'approve' | 'reject';
  } | null>(null);
  const [reason, setReason] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function resolve(): Promise<void> {
    if (!pending) return;
    setBusy(true);
    setError(null);
    try {
      await api(token, `/v1/approvals/${pending.approval.id}/${pending.effect}`, {
        method: 'POST',
        body: { reason },
      });
      setPending(null);
      setReason('');
      onChanged();
    } catch (e) {
      // Surfaced verbatim: SELF_APPROVAL and ALREADY_RESOLVED mean different things
      // and the operator needs to know which happened.
      setError(e instanceof ApiError ? `${e.code}: ${e.message}` : String(e));
    } finally {
      setBusy(false);
    }
  }

  if (approvals.length === 0) {
    return <Typography color="text.secondary">No approvals waiting.</Typography>;
  }

  return (
    <Stack spacing={2}>
      {approvals.map((a) => (
        <Card key={a.id} variant="outlined">
          <CardContent>
            <Stack
              direction={{ xs: 'column', sm: 'row' }}
              spacing={1}
              sx={{ justifyContent: 'space-between' }}
            >
              <Box>
                <Typography variant="h6" sx={{ fontFamily: 'monospace' }}>
                  {a.action_key}
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  {a.resource_type} · {a.resource_id}
                  {a.resource_version ? ` · v${a.resource_version}` : ''}
                </Typography>
              </Box>
              <Chip
                size="small"
                label={expiresIn(a.expires_at)}
                color={a.overdue ? 'error' : 'default'}
              />
            </Stack>

            <Stack direction="row" spacing={1} sx={{ mt: 1.5, flexWrap: 'wrap', gap: 0.5 }}>
              {a.reason_codes.map((r) => (
                <Chip key={r} size="small" variant="outlined" label={r} />
              ))}
            </Stack>

            <Typography variant="body2" sx={{ mt: 1.5 }}>
              Requested by <strong>{a.agent_name}</strong>
              {a.agent_owner ? <> · owner {a.agent_owner}</> : null}
            </Typography>

            {/* Equal weight. Neither is the default. */}
            <Stack direction="row" spacing={1} sx={{ mt: 2 }}>
              <Button
                variant="outlined"
                color="success"
                onClick={() => setPending({ approval: a, effect: 'approve' })}
              >
                Approve
              </Button>
              <Button
                variant="outlined"
                color="error"
                onClick={() => setPending({ approval: a, effect: 'reject' })}
              >
                Reject
              </Button>
            </Stack>
          </CardContent>
        </Card>
      ))}

      <Dialog
        open={pending !== null}
        onClose={() => !busy && setPending(null)}
        fullWidth
        maxWidth="sm"
      >
        <DialogTitle>
          {pending?.effect === 'approve' ? 'Approve' : 'Reject'} {pending?.approval.action_key}
        </DialogTitle>
        <DialogContent>
          <Typography variant="body2" color="text.secondary" gutterBottom>
            {pending?.approval.resource_type} · {pending?.approval.resource_id}
          </Typography>
          {error ? (
            <Alert severity="error" sx={{ my: 1 }}>
              {error}
            </Alert>
          ) : null}
          <TextField
            autoFocus
            fullWidth
            multiline
            rows={2}
            label="Reason (recorded in the audit trail)"
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            sx={{ mt: 1 }}
          />
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setPending(null)} disabled={busy}>
            Cancel
          </Button>
          <Button
            onClick={() => void resolve()}
            disabled={busy}
            color={pending?.effect === 'approve' ? 'success' : 'error'}
            variant="contained"
          >
            {busy ? 'Working…' : `Confirm ${pending?.effect}`}
          </Button>
        </DialogActions>
      </Dialog>
    </Stack>
  );
}
