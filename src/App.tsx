import { CorrelationDashboard } from './components/CorrelationDashboard';
import React, { useEffect, useRef } from 'react';
import { LogOut, ShieldCheck } from 'lucide-react';
import { LoginView } from './components/LoginView';
import { AppProvider, useApp } from './context/AppContext';
import { ErrorBoundary } from './components/ErrorBoundary';
import { Sidebar } from './components/Sidebar';
import { TopHeader } from './components/TopHeader';
import { DashboardView } from './components/DashboardView';
import { WatchListView } from './components/WatchListView';
import { FindingsView } from './components/FindingsView';
import { ThreatDataView } from './components/ThreatDataView';
import { ThreatIntelligenceSearch } from './components/ThreatIntelligenceSearch';
import { VulnerabilitySearchView } from './components/VulnerabilitySearchView';
import { ThreatAnalyticsView } from './components/ThreatAnalyticsView';
import { CpeMatcherView } from './components/CpeMatcherView';
import { AdvisoriesView } from './components/AdvisoriesView';
import { PipelineExecutionsView } from './components/PipelineExecutionsView';
import { AlertedCVEsView } from './components/AlertedCVEsView';
import { ThreatFeedsView } from './components/ThreatFeedsView';
import { RecipientsView } from './components/RecipientsView';
import { AdvisoryTemplateView } from './components/AdvisoryTemplateView';
import { DailyDigestView } from './components/DailyDigestView';
import { EmailHistoryView } from './components/EmailHistoryView';
import { EmailQueueView } from './components/EmailQueueView';
import { OperationalLogsView } from './components/OperationalLogsView';
import { SystemHealthView } from './components/SystemHealthView';
import { ActionCenter } from './components/ActionCenter';
import { SettingsView } from './components/SettingsView';
import { ArchiveRetentionView } from './components/ArchiveRetentionView';
import { AliasesView } from './components/AliasesView';

export const MainContent: React.FC = () => {
  const { activeTab } = useApp();
  const previousTab = useRef(activeTab);
  useEffect(() => {
    if (previousTab.current === activeTab) return;
    previousTab.current = activeTab;
    window.scrollTo({ top: 0, behavior: 'instant' });
    document.getElementById('page-title')?.focus({ preventScroll: true });
  }, [activeTab]);

  return (
    <main
      id="main-content"
      aria-labelledby="page-title"
      className="ui-main flex-1 px-4 sm:px-6 lg:px-8 py-6 pb-16"
    >
      {activeTab === 'dashboard' && <DashboardView />}
      {activeTab === 'watchlist' && <WatchListView />}
      {activeTab === 'findings' && <FindingsView />}
      {activeTab === 'threat-intelligence-search' && <ThreatIntelligenceSearch />}
      {activeTab === 'vulnerability-search' && <VulnerabilitySearchView />}
      {activeTab === 'threat-analytics' && <ThreatAnalyticsView />}
      {activeTab === 'cpe-matcher' && <CpeMatcherView />}
      {activeTab === 'threat-data' && <ThreatDataView />}
      {activeTab === 'advisories' && <AdvisoriesView />}
      {activeTab === 'correlation' && <CorrelationDashboard />}
      {activeTab === 'pipeline' && <PipelineExecutionsView />}
      {activeTab === 'alerted-cves' && <AlertedCVEsView />}
      {activeTab === 'feeds' && <ThreatFeedsView />}
      {activeTab === 'recipients' && <RecipientsView />}
      {activeTab === 'template' && <AdvisoryTemplateView />}
      {activeTab === 'daily-digest' && <DailyDigestView />}
      {activeTab === 'emails' && <EmailHistoryView />}
      {activeTab === 'email-queue' && <EmailQueueView />}
      {activeTab === 'logs' && <OperationalLogsView />}
      {activeTab === 'health' && <SystemHealthView />}
      {activeTab === 'settings' && <SettingsView />}
      {activeTab === 'archive' && <ArchiveRetentionView />}
      {activeTab === 'aliases' && <AliasesView />}
      {activeTab === 'action-center' && <ActionCenter />}
    </main>
  );
};

const Footer: React.FC = () => {
  return (
    <footer className="mt-auto border-t border-zinc-800/80 dark:border-zinc-800/80 light:border-zinc-200 bg-zinc-950/80 dark:bg-zinc-950/80 light:bg-white py-4 text-xs text-zinc-500 transition-colors duration-200">
      <div className="px-4 sm:px-6 flex flex-col sm:flex-row items-center justify-between gap-3 text-[11px]">
        <div className="flex items-center gap-2">
          <ShieldCheck className="h-3.5 w-3.5 text-emerald-500" />
          <span className="font-semibold text-zinc-400 dark:text-zinc-400 light:text-zinc-600">
            BA Threat Intel Enterprise
          </span>
          <span>•</span>
          <span>PostgreSQL persistence</span>
        </div>
        <div className="flex flex-wrap items-center justify-center gap-x-3 gap-y-1 text-zinc-500">
          <span>Server scheduler</span>
          <span>•</span>
          <span>Strict CPE 2.3 + PURL</span>
          <span>•</span>
          <span>Role-based access</span>
        </div>
      </div>
    </footer>
  );
};

const AppShell: React.FC = () => {
  const {
    theme,
    session,
    loading,
    error,
    sessionExpired,
    clearError,
    logout,
    pending,
    mobileNavOpen,
    setMobileNavOpen,
  } = useApp();
  if (loading || !session) return <LoginView sessionExpired={sessionExpired} />;

  return (
    <div
      className={`min-h-screen flex selection:bg-zinc-800 selection:text-zinc-100 transition-colors duration-200 ${
        theme === 'dark' ? 'dark bg-[#09090b] text-zinc-100' : 'light bg-zinc-50 text-zinc-900'
      }`}
    >
      <a className="ui-skip-link" href="#main-content">
        Skip to main content
      </a>
      {/* Left Side Panel Navigation */}
      {mobileNavOpen && (
        <button
          type="button"
          className="ui-nav-backdrop md:hidden"
          aria-label="Close navigation"
          onClick={() => setMobileNavOpen(false)}
        />
      )}
      <Sidebar />

      {/* Main Content Area */}
      <div className="flex-1 flex flex-col min-w-0 min-h-screen">
        <TopHeader />
        <div className="ui-session-bar flex items-center justify-between gap-3 border-b border-zinc-800/80 dark:border-zinc-800/80 light:border-zinc-200 bg-zinc-900/30 dark:bg-zinc-900/30 light:bg-white/70 px-4 sm:px-6 py-2.5 text-xs">
          <div className="flex min-w-0 items-center gap-2.5">
            <span className="grid h-7 w-7 shrink-0 place-items-center rounded-full border border-zinc-700/70 dark:border-zinc-700/70 light:border-zinc-300 bg-zinc-800/70 dark:bg-zinc-800/70 light:bg-zinc-100 font-semibold text-zinc-200 dark:text-zinc-200 light:text-zinc-700">
              {session.username.slice(0, 1).toUpperCase()}
            </span>
            <span className="truncate font-medium text-zinc-200 dark:text-zinc-200 light:text-zinc-800">
              {session.username}
            </span>
            <span className="rounded-md border border-zinc-700/70 dark:border-zinc-700/70 light:border-zinc-300 px-1.5 py-0.5 text-[9px] font-semibold tracking-wide text-zinc-400 dark:text-zinc-400 light:text-zinc-600">
              {session.role}
            </span>
            {pending > 0 && (
              <span role="status" className="text-[10px] text-blue-400">
                Saving changes…
              </span>
            )}
          </div>
          <button
            type="button"
            onClick={() => void logout()}
            className="inline-flex shrink-0 items-center gap-1.5 rounded-lg px-2.5 py-1.5 font-medium text-zinc-400 transition hover:bg-zinc-800/70 hover:text-zinc-100 dark:hover:bg-zinc-800/70 dark:hover:text-zinc-100 light:hover:bg-zinc-100 light:hover:text-zinc-900"
          >
            <LogOut className="h-3.5 w-3.5" />
            <span>Sign out</span>
          </button>
        </div>
        {error && (
          <div
            role="alert"
            className="mx-4 mt-3 flex items-start justify-between gap-4 rounded-xl border border-rose-800/50 light:border-rose-200 bg-rose-950/70 light:bg-rose-50 px-4 py-3 text-xs text-rose-100 light:text-rose-800 sm:mx-6"
          >
            <span>{error}</span>
            <button onClick={clearError} className="shrink-0 underline underline-offset-2">
              Dismiss
            </button>
          </div>
        )}
        <div className="ui-workspace flex-1 min-w-0 flex flex-col w-full mx-auto">
          <MainContent />
          <Footer />
        </div>
      </div>
    </div>
  );
};

export default function App() {
  return (
    <ErrorBoundary>
      <AppProvider>
        <AppShell />
      </AppProvider>
    </ErrorBoundary>
  );
}
