import React, { useEffect, useRef, useState } from 'react';
import {
  AlertTriangle,
  ArrowLeft,
  ArrowRight,
  Brain,
  ChevronRight,
  Clock3,
  Filter,
  RotateCw,
  Search,
  X,
} from 'lucide-react';
import { useApp } from '../context/AppContext';
import type { OperationalEvent } from '../types';
import { EventDetailPanel } from './EventDetailPanel';
import { formatDate, formatTime, timezoneLabel } from '../utils/dateTime';
import { humanizeEventKey } from '../utils/eventText';
import './logs-view.css';

function contextPreview(event: OperationalEvent) {
  const context = event.context || {};
  const priority = [
    'modelId',
    'modelCount',
    'trained',
    'failed',
    'saved',
    'skipped',
    'samplesCollected',
    'modelVersion',
    'threshold',
    'component',
  ];
  return [...new Set([...priority, ...Object.keys(context)])]
    .filter(
      (key) =>
        context[key] !== undefined &&
        context[key] !== null &&
        ['string', 'number', 'boolean'].includes(typeof context[key]) &&
        !['error', 'stack', 'timestamp'].includes(key),
    )
    .slice(0, 5)
    .map((key) => ({
      label: humanizeEventKey(key),
      value: typeof context[key] === 'boolean' ? (context[key] ? 'Yes' : 'No') : String(context[key]),
    }));
}

export const MlLogsView: React.FC = () => {
  const { fetchEvents, settings } = useApp();
  const [query, setQuery] = useState('');
  const [level, setLevel] = useState('');
  const [history, setHistory] = useState<string[]>([]);
  const cursor = history.at(-1) || '';
  const [next, setNext] = useState<string | null>(null);
  const [events, setEvents] = useState<OperationalEvent[]>([]);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(true);
  const [updatedAt, setUpdatedAt] = useState('');
  const [selectedEvent, setSelectedEvent] = useState<OperationalEvent | null>(null);
  const [refresh, setRefresh] = useState(0);
  const searchRef = useRef<HTMLInputElement>(null);
  const pendingRequest = useRef(false);
  const filtered = Boolean(query || level);
  const clearFilters = () => {
    setQuery('');
    setLevel('');
    setHistory([]);
  };

  useEffect(() => {
    let disposed = false;
    setLoading(true);
    pendingRequest.current = true;
    setError('');
    const timer = setTimeout(() => {
      fetchEvents(
        new URLSearchParams({
          category: 'ML',
          ...(level && { level }),
          ...(query && { q: query }),
          ...(cursor && { before: cursor }),
        }).toString(),
      )
        .then((result) => {
          if (!disposed) {
            setEvents(result.events);
            setNext(result.nextCursor);
            setUpdatedAt(new Date().toISOString());
          }
        })
        .catch((error: unknown) => {
          if (!disposed) setError(error instanceof Error ? error.message : 'Please try again.');
        })
        .finally(() => {
          if (!disposed) {
            pendingRequest.current = false;
            setLoading(false);
          }
        });
    }, 250);
    return () => {
      disposed = true;
      clearTimeout(timer);
    };
  }, [query, level, cursor, refresh]);

  useEffect(() => {
    if (cursor) return;
    const update = () => {
      if (!pendingRequest.current && document.visibilityState !== 'hidden') setRefresh((value) => value + 1);
    };
    const interval = setInterval(update, 10_000);
    document.addEventListener('visibilitychange', update);
    return () => {
      clearInterval(interval);
      document.removeEventListener('visibilitychange', update);
    };
  }, [cursor]);

  const errors = events.filter((event) => event.level === 'ERROR').length;
  const warnings = events.filter((event) => event.level === 'WARNING').length;
  return (
    <section id="logs-ml-panel" role="tabpanel" aria-labelledby="logs-ml-tab" className="ml-logs">
      <header className="ml-logs-header">
        <div className="ml-logs-heading">
          <span className="ml-logs-icon">
            <Brain size={21} aria-hidden="true" />
          </span>
          <div>
            <h2>Machine learning activity</h2>
            <p>Follow model loading, training cycles, and prediction decisions.</p>
          </div>
        </div>
        <span className={`ml-logs-live ${cursor ? 'is-paused' : ''}`}>
          <span aria-hidden="true" />
          {cursor ? 'History · auto-refresh paused' : 'Auto-refresh · every 10s'}
        </span>
      </header>

      <div className="ui-panel ml-logs-filters">
        <div className="ml-logs-filter-title">
          <Filter size={14} aria-hidden="true" /> Filter activity
        </div>
        <div className="ml-logs-filter-grid">
          <label className="ml-logs-search">
            <span>Search events</span>
            <div className="ml-logs-search-control">
              <Search size={16} aria-hidden="true" />
              <input
                ref={searchRef}
                type="search"
                aria-label="Search ML events"
                maxLength={200}
                value={query}
                placeholder="Search event codes, messages, or context…"
                onChange={(event) => {
                  setQuery(event.target.value);
                  setHistory([]);
                }}
              />
              {query && (
                <button
                  type="button"
                  aria-label="Clear ML search"
                  onClick={() => {
                    setQuery('');
                    setHistory([]);
                    searchRef.current?.focus();
                  }}
                >
                  <X size={15} aria-hidden="true" />
                </button>
              )}
            </div>
          </label>
          <label>
            <span>Event level</span>
            <select
              aria-label="ML event level"
              value={level}
              onChange={(event) => {
                setLevel(event.target.value);
                setHistory([]);
              }}
            >
              <option value="">All levels</option>
              <option value="INFO">Info</option>
              <option value="WARNING">Warning</option>
              <option value="ERROR">Error</option>
            </select>
          </label>
          <button
            type="button"
            className="ml-logs-button ml-logs-refresh"
            disabled={loading}
            onClick={() => setRefresh((value) => value + 1)}
          >
            <RotateCw size={15} className={loading ? 'animate-spin' : ''} aria-hidden="true" />
            Refresh
          </button>
        </div>
        {filtered && (
          <div className="ml-logs-filter-summary">
            <span>
              Filtered activity
              {level ? ` · ${level === 'INFO' ? 'Info' : level === 'WARNING' ? 'Warning' : 'Error'}` : ''}
            </span>
            <button type="button" onClick={clearFilters}>
              <X size={13} aria-hidden="true" />
              Clear filters
            </button>
          </div>
        )}
      </div>

      {error && (
        <div role="alert" className="ml-logs-error">
          <AlertTriangle size={19} aria-hidden="true" />
          <div>
            <strong>Could not {events.length ? 'refresh' : 'load'} ML activity</strong>
            <p>{error}</p>
            {events.length > 0 && <p>The last loaded events are still shown below.</p>}
          </div>
          <button
            type="button"
            className="ml-logs-button"
            disabled={loading}
            onClick={() => setRefresh((value) => value + 1)}
          >
            Try again
          </button>
        </div>
      )}

      <div className="ui-panel ml-logs-events" aria-busy={loading}>
        <div className="ml-logs-events-heading">
          <div>
            <h3>Event history</h3>
            <p>
              {cursor ? 'Earlier activity' : 'Latest activity'}
              <span aria-hidden="true"> · </span>Times in {timezoneLabel(settings.timezone)}
            </p>
          </div>
          <div className="ml-logs-page-count" role="status" aria-live="polite">
            <span>{loading ? 'Updating…' : `${events.length} events on this page`}</span>
            {events.length > 0 && (
              <>
                <span className="ml-logs-count-error">
                  {errors} {errors === 1 ? 'error' : 'errors'}
                </span>
                <span className="ml-logs-count-warning">
                  {warnings} {warnings === 1 ? 'warning' : 'warnings'}
                </span>
              </>
            )}
          </div>
        </div>
        {!events.length && !error && (
          <div className="ml-logs-empty" role="status">
            {loading ? (
              <RotateCw size={25} className="animate-spin" aria-hidden="true" />
            ) : (
              <Brain size={27} aria-hidden="true" />
            )}
            <h3>{loading ? 'Loading activity…' : filtered ? 'No matching events' : 'No ML activity yet'}</h3>
            <p>
              {loading
                ? 'Retrieving the event history.'
                : filtered
                  ? 'Try another search or clear your filters to see more activity.'
                  : 'Runtime, training, and prediction events will appear here when recorded.'}
            </p>
            {filtered && !loading && (
              <button type="button" className="ml-logs-button" onClick={clearFilters}>
                Clear filters
              </button>
            )}
          </div>
        )}
        {events.length > 0 && (
          <table className="ml-logs-table">
            <caption className="sr-only">ML events with model details, run and trace correlations, and local timestamps.</caption>
            <thead>
              <tr>
                <th scope="col">Level</th>
                <th scope="col">Model activity &amp; details</th>
                <th scope="col">Run &amp; trace correlation</th>
                <th scope="col">Recorded</th>
              </tr>
            </thead>
            <tbody>
              {events.map((event) => {
                const preview = contextPreview(event);
                return (
                  <tr
                    key={event.id}
                    onClick={() => setSelectedEvent(event)}
                    className="cursor-pointer"
                  >
                    <td className="ml-logs-level-cell">
                      <span className={`ml-logs-level is-${event.level.toLowerCase()}`}>
                        <span aria-hidden="true" />
                        {event.level === 'INFO' ? 'Info' : event.level === 'WARNING' ? 'Warning' : 'Error'}
                      </span>
                    </td>
                    <td className="ml-logs-event-cell">
                      <code className="ml-logs-code">{event.code}</code>
                      <button
                        type="button"
                        className="ml-logs-event-title"
                        onClick={() => setSelectedEvent(event)}
                      >
                        {event.message}
                        <ChevronRight size={15} aria-hidden="true" />
                      </button>
                      {preview.length > 0 && (
                        <dl className="ml-logs-context">
                          {preview.map((item) => (
                            <div key={item.label}>
                              <dt>{item.label}</dt>
                              <dd>{item.value}</dd>
                            </div>
                          ))}
                        </dl>
                      )}
                      {event.level === 'ERROR' && event.context?.error !== undefined && (
                        <p className="ml-logs-error-preview" title={String(event.context.error)}>
                          {typeof event.context.error === 'string'
                            ? event.context.error
                            : 'Error details available'}
                        </p>
                      )}
                    </td>
                    <td className="ml-logs-correlation-cell">
                      {event.runId ? (
                        <span className="ml-logs-run" title={event.runId}>Run {event.runId}</span>
                      ) : (
                        <span className="ml-logs-unlinked">No run reference</span>
                      )}
                      {event.trackingId && (
                        <span className="ml-logs-run" title={event.trackingId}>Trace {event.trackingId}</span>
                      )}
                      {event.sequence !== undefined && (
                        <span className="ml-logs-run">Worker sequence #{event.sequence}</span>
                      )}
                    </td>
                    <td className="ml-logs-time-cell">
                      <time dateTime={event.timestamp} title={event.timestamp}>
                        {formatDate(event.timestamp, settings.timezone)}
                        <span>{formatTime(event.timestamp, settings.timezone)}</span>
                      </time>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
        <footer className="ml-logs-footer">
          <span className="ml-logs-update">
            <Clock3 size={13} aria-hidden="true" />
            {updatedAt ? `Last updated ${formatTime(updatedAt, settings.timezone)}` : 'Waiting for activity'}
            {cursor && ` · Page ${history.length + 1}`}
          </span>
          <nav aria-label="ML event pages">
            <button
              type="button"
              className="ml-logs-button"
              disabled={!cursor || loading}
              onClick={() => {
                setHistory([]);
                setRefresh((value) => value + 1);
              }}
            >
              Latest
            </button>
            <button
              type="button"
              className="ml-logs-button"
              disabled={!cursor || loading}
              onClick={() => setHistory((value) => value.slice(0, -1))}
            >
              <ArrowLeft size={14} aria-hidden="true" />
              Newer
            </button>
            <button
              type="button"
              className="ml-logs-button"
              disabled={!next || loading || Boolean(error)}
              onClick={() => {
                if (next) setHistory((value) => [...value, next]);
              }}
            >
              Older
              <ArrowRight size={14} aria-hidden="true" />
            </button>
          </nav>
        </footer>
      </div>
      {selectedEvent && (
        <EventDetailPanel
          event={selectedEvent}
          timezone={settings.timezone}
          onClose={() => setSelectedEvent(null)}
        />
      )}
    </section>
  );
};
