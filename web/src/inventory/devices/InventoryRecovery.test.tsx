import { describe, expect, it } from 'vitest';
import { render, screen } from '@testing-library/react';
import { ApiError } from '../../api/client';
import { CachedObservedFacts } from './DeviceDetail';
import { ErrorNotice } from '../ui/ErrorNotice';

describe('Inventory recovery evidence', () => {
  it('labels cached facts without claiming a current graph read', () => {
    const error = Object.assign(new ApiError(503, 'observed store unavailable'), {
      detail: {
        snapshot_key: 'snap-1', snapshot_age_s: 90,
        summary: { hostname: 'Firewall', graph_uid: 'dev:physical/1', platform: 'VSX', lifecycle: 'active', collection_state: 'stale' },
        placement: { mode: 'assigned', desired_site_code: 'FRA', published_site_code: 'AMS', pending: true },
        observations: [{ source_key: 'controller', host: 'controller.example', state: 'stale', authority: 'partial' }],
      },
    });
    render(<CachedObservedFacts error={error}/>);
    expect(screen.getByRole('region', { name: 'Cached device facts' })).toHaveTextContent('Cached inventory facts');
    expect(screen.getByText('90 seconds')).toBeInTheDocument();
    expect(screen.getByText('Pending publication')).toBeInTheDocument();
    expect(screen.getByRole('row', { name: /controller controller.example stale partial/ })).toBeInTheDocument();
  });

  it('does not fabricate cached facts from an unavailable error without a summary', () => {
    render(<CachedObservedFacts error={Object.assign(new ApiError(503, 'unavailable'), { detail: { snapshot_key: 'snap-1' } })}/>);
    expect(screen.queryByRole('region')).not.toBeInTheDocument();
  });

  it.each([
    ['inventory_changed', 'Inventory changed after the selection'],
    ['stale_revision', 'Record changed after loading'],
    ['preview_expired', 'Preview expired'],
    ['idempotency_conflict', 'Request key used for another operation'],
    ['normalization_migrated', 'Normalization settings read-only'],
    ['validation', 'Request not valid'],
    ['observed_store_unavailable', 'Observed inventory store not available'],
    ['not_found', 'Inventory record not found'],
  ])('states the specific error for %s', (code, message) => {
    render(<ErrorNotice error={Object.assign(new ApiError(409, 'Backend detail'), { code })}/>);
    expect(screen.getByRole('alert')).toHaveTextContent(message);
  });

  it('shows current revision and references without discarding the draft', () => {
    render(<ErrorNotice error={Object.assign(new ApiError(409, 'changed'), { code: 'stale_revision', currentRevision: 9, references: ['target-1'] })}/>);
    expect(screen.getByRole('alert')).toHaveTextContent('Current server revision: 9');
    expect(screen.getByRole('list', { name: 'Conflict references' })).toHaveTextContent('target-1');
  });
});
