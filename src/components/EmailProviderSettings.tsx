import React, { useEffect, useState } from 'react';
import { KeyRound, Mail, Save, Send, Server, Globe, RotateCcw, LoaderCircle } from 'lucide-react';
import { useApp } from '../context/AppContext';
import { isSmtpEmailProvider, type EmailConfiguration, type EmailProvider } from '../types';

const methodName = (provider: EmailProvider) =>
  isSmtpEmailProvider(provider)
    ? provider === 'SENDGRID_SMTP'
      ? 'SendGrid SMTP'
      : 'SMTP'
    : provider === 'MAILJET_API'
      ? 'Mailjet API'
      : 'Email API';
const initialForm = (configuration: EmailConfiguration): EmailConfiguration => ({
  ...configuration,
  provider: isSmtpEmailProvider(configuration.provider) ? configuration.provider : configuration.provider,
  apiKey: '',
  mailjetApiSecret: '',
  apiEndpoint: configuration.apiEndpoint || '',
  apiHeaderKey: configuration.apiHeaderKey || 'Authorization',
  apiAuthPrefix: configuration.apiAuthPrefix ?? 'Bearer',
  apiSourceDomain: configuration.apiSourceDomain || '',
  smtpHost: configuration.smtpHost || (configuration.provider === 'SENDGRID_SMTP' ? 'smtp.sendgrid.net' : ''),
  smtpPort: configuration.smtpPort || 587,
  smtpSecurity: configuration.smtpSecurity || 'STARTTLS',
  smtpUsername: configuration.smtpUsername || (configuration.provider === 'SENDGRID_SMTP' ? 'apikey' : ''),
  smtpPassword: '',
});

export function EmailProviderSettings() {
  const { emailConfig, configureEmailProvider, sendTestEmail, pending } = useApp();
  const [form, setForm] = useState<EmailConfiguration>(() => initialForm(emailConfig));
  const [dirty, setDirty] = useState(false);
  const [message, setMessage] = useState('');
  const [testEmail, setTestEmail] = useState('');
  const savedVersion = JSON.stringify(emailConfig);
  useEffect(() => {
    setForm(initialForm(emailConfig));
    setDirty(false);
  }, [savedVersion]);
  const update = (value: Partial<EmailConfiguration>) => {
    setForm((old) => ({ ...old, ...value }));
    setDirty(true);
    setMessage('');
  };
  const selectProvider = (provider: EmailProvider) => {
    update({
      provider,
      apiKey: '',
      smtpPassword: '',
      mailjetApiSecret: '',
      ...(provider === 'SENDGRID_SMTP'
        ? {
            smtpHost: 'smtp.sendgrid.net',
            smtpPort: 587,
            smtpSecurity: 'STARTTLS' as const,
            smtpUsername: 'apikey',
          }
        : {}),
    });
  };
  const isSmtp = isSmtpEmailProvider(form.provider);
  const isMailjet = form.provider === 'MAILJET_API';
  const isSendGridSmtp = form.provider === 'SENDGRID_SMTP';
  const isGmailSmtp = form.smtpHost.trim().toLowerCase() === 'smtp.gmail.com';
  const hasSavedApiKey = form.provider === emailConfig.provider && !!emailConfig.hasApiKey;
  const hasSavedSmtpPassword = form.provider === emailConfig.provider && !!emailConfig.hasSmtpPassword;
  const hasSavedMailjetSecret = form.provider === emailConfig.provider && !!emailConfig.hasMailjetApiSecret;

  return (
    <section className="ui-card space-y-5" aria-labelledby="email-settings-heading">
      <div className="settings-section-heading flex flex-wrap items-start justify-between gap-4">
        <div className="flex items-start gap-3">
          <span className="ui-section-icon">
            <Mail className="h-4 w-4" />
          </span>
          <div>
            <h2 id="email-settings-heading" className="ui-card-title">
              Email delivery
            </h2>
            <p className="ui-description mt-1">Choose SMTP relay or a custom HTTPS email API.</p>
          </div>
        </div>
        <span className="inline-flex items-center gap-1.5 rounded-full border border-zinc-700 light:border-zinc-200 px-2.5 py-1 text-[11px] text-zinc-400">
          <Mail className="h-3.5 w-3.5" /> Saved: {methodName(emailConfig.provider)}
        </span>
      </div>

      <form
        className="space-y-5"
        onSubmit={async (event) => {
          event.preventDefault();
          setMessage('');
          if (await configureEmailProvider(form)) {
            setForm((old) => ({ ...old, apiKey: '', smtpPassword: '', mailjetApiSecret: '' }));
            setDirty(false);
            setMessage(`${methodName(form.provider)} configuration saved.`);
          }
        }}
      >
        <div className="grid gap-4 sm:grid-cols-2">
          <fieldset className="settings-provider-picker sm:col-span-2">
            <legend>Delivery method</legend>
            <div>
              {(
                [
                  { id: 'SMTP', title: 'SMTP relay', description: 'Your existing mail server', icon: Server },
                  {
                    id: 'SENDGRID_SMTP',
                    title: 'SendGrid SMTP',
                    description: 'Relay through SendGrid',
                    icon: Send,
                  },
                  {
                    id: 'MAILJET_API',
                    title: 'Mailjet API',
                    description: 'Direct Mailjet integration',
                    icon: Mail,
                  },
                  {
                    id: 'API',
                    title: 'Custom email API',
                    description: 'Your HTTPS delivery endpoint',
                    icon: Globe,
                  },
                ] as const
              ).map(({ id, title, description, icon: Icon }) => (
                <button
                  type="button"
                  key={id}
                  aria-pressed={
                    (isSendGridSmtp
                      ? 'SENDGRID_SMTP'
                      : isSmtp
                        ? 'SMTP'
                        : isMailjet
                          ? 'MAILJET_API'
                          : 'API') === id
                  }
                  disabled={pending > 0}
                  onClick={() => selectProvider(id)}
                >
                  <Icon size={18} aria-hidden="true" />
                  <span>
                    <strong>{title}</strong>
                    <small>{description}</small>
                  </span>
                  <span className="settings-choice-dot" aria-hidden="true" />
                </button>
              ))}
            </div>
          </fieldset>
          <label htmlFor="email-from-name">
            Sender name
            <input
              id="email-from-name"
              className="ui-field"
              value={form.fromName}
              maxLength={100}
              placeholder="BA Threat Intel Security"
              onChange={(event) => update({ fromName: event.target.value })}
            />
          </label>
          <label htmlFor="email-from-address" className="sm:col-span-2">
            Sender email
            <input
              id="email-from-address"
              className="ui-field"
              type="email"
              value={form.fromEmail}
              maxLength={254}
              required={isSmtp ? !!form.smtpHost : true}
              placeholder={
                isSmtp && !form.smtpHost ? 'Use the deployment sender address' : 'security@your-domain.com'
              }
              onChange={(event) => update({ fromEmail: event.target.value })}
            />
            <span className="ui-description mt-1.5 block">
              Use an address verified by your email service.
            </span>
          </label>

          {isSmtp ? (
            <>
              <label htmlFor="smtp-host">
                SMTP host
                <input
                  id="smtp-host"
                  className="ui-field"
                  value={form.smtpHost}
                  maxLength={253}
                  placeholder="smtp.example.com"
                  onChange={(event) =>
                    update({
                      smtpHost: event.target.value,
                      ...(event.target.value ? {} : { smtpUsername: '', smtpPassword: '' }),
                    })
                  }
                />
                <span className="ui-description mt-1.5 block">
                  Leave blank to use deployment settings. Custom hosts require outbound permission.
                </span>
              </label>
              {form.smtpHost && (
                <>
                  <label htmlFor="smtp-port">
                    SMTP port
                    <input
                      id="smtp-port"
                      type="number"
                      min={1}
                      max={65535}
                      className="ui-field"
                      value={form.smtpPort}
                      onChange={(event) => {
                        const port = Number(event.target.value);
                        update({
                          smtpPort: port,
                          ...(port === 465
                            ? { smtpSecurity: 'IMPLICIT_TLS' as const }
                            : port === 587
                              ? { smtpSecurity: 'STARTTLS' as const }
                              : {}),
                        });
                      }}
                    />
                  </label>
                  <label htmlFor="smtp-security">
                    SMTP encryption
                    <select
                      id="smtp-security"
                      className="ui-field"
                      value={form.smtpSecurity}
                      onChange={(event) =>
                        update({ smtpSecurity: event.target.value as EmailConfiguration['smtpSecurity'] })
                      }
                    >
                      <option value="STARTTLS">STARTTLS</option>
                      <option value="IMPLICIT_TLS">Implicit TLS</option>
                    </select>
                  </label>
                  <label htmlFor="smtp-username">
                    {isGmailSmtp
                      ? 'Authentication username'
                      : isSendGridSmtp
                        ? 'API key as username'
                        : 'SMTP username'}
                    <input
                      id="smtp-username"
                      className="ui-field"
                      autoComplete="username"
                      value={form.smtpUsername}
                      placeholder={
                        isGmailSmtp ? 'yourusername@gmail.com' : isSendGridSmtp ? 'apikey' : 'SMTP username'
                      }
                      onChange={(event) => update({ smtpUsername: event.target.value })}
                    />
                  </label>
                  <label htmlFor="smtp-password" className="sm:col-span-2">
                    {isGmailSmtp ? 'Authentication password' : isSendGridSmtp ? 'API key' : 'SMTP password'}
                    <input
                      id="smtp-password"
                      type="password"
                      autoComplete="new-password"
                      spellCheck={false}
                      className="ui-field"
                      value={form.smtpPassword}
                      maxLength={4096}
                      required={!!form.smtpUsername && !hasSavedSmtpPassword}
                      placeholder={
                        hasSavedSmtpPassword
                          ? 'Credential saved — leave blank to keep it'
                          : isGmailSmtp
                            ? '16-character Gmail App Password'
                            : isSendGridSmtp
                              ? 'Enter your SendGrid API key'
                              : 'Enter SMTP password'
                      }
                      onChange={(event) => update({ smtpPassword: event.target.value })}
                    />
                    <span className="ui-description mt-1.5 flex items-center gap-1.5">
                      <KeyRound className="h-3 w-3" /> Encrypted on the server. Leave blank to keep a saved
                      credential.
                    </span>
                  </label>
                </>
              )}
              <details className="settings-provider-help sm:col-span-2">
                <summary>SMTP setup notes</summary>
                <p className="ui-description">
                  Gmail configuration: host smtp.gmail.com; use your full Gmail address and generated
                  16-character App Password. Port 587 uses STARTTLS (recommended); port 465 uses implicit TLS.
                  SMTP also supports SendGrid (username <code>apikey</code>), Maileroo, Lettr, Mailjet, and
                  other relays.
                </p>
              </details>
            </>
          ) : isMailjet ? (
            <>
              <label htmlFor="email-mailjet-api-key" className="sm:col-span-2">
                Mailjet API Key
                <input
                  id="email-mailjet-api-key"
                  type="password"
                  autoComplete="new-password"
                  spellCheck={false}
                  className="ui-field"
                  value={form.apiKey}
                  maxLength={4096}
                  required={!hasSavedApiKey}
                  placeholder={
                    hasSavedApiKey
                      ? 'API Key saved — leave blank to keep it'
                      : 'Mailjet API Key (MJ_APIKEY_PUBLIC)'
                  }
                  onChange={(event) => update({ apiKey: event.target.value })}
                />
                <span className="ui-description mt-1.5 flex items-center gap-1.5">
                  <KeyRound className="h-3 w-3" /> Encrypted on the server. Saved keys are never displayed.
                </span>
              </label>
              <label htmlFor="email-mailjet-api-secret" className="sm:col-span-2">
                Mailjet API Secret
                <input
                  id="email-mailjet-api-secret"
                  type="password"
                  autoComplete="new-password"
                  spellCheck={false}
                  className="ui-field"
                  value={form.mailjetApiSecret}
                  maxLength={4096}
                  required={!hasSavedMailjetSecret}
                  placeholder={
                    hasSavedMailjetSecret
                      ? 'API Secret saved — leave blank to keep it'
                      : 'Mailjet API Secret (MJ_APIKEY_PRIVATE)'
                  }
                  onChange={(event) => update({ mailjetApiSecret: event.target.value })}
                />
                <span className="ui-description mt-1.5 flex items-center gap-1.5">
                  <KeyRound className="h-3 w-3" /> Encrypted on the server. Sent as Basic auth password.
                </span>
              </label>
              <p className="ui-description sm:col-span-2">
                The endpoint is fixed to https://api.mailjet.com/v3.1/send. Ensure the hostname is in
                EGRESS_ALLOWED_HOSTS.
              </p>
            </>
          ) : (
            <>
              <label htmlFor="email-api-endpoint" className="sm:col-span-2">
                API endpoint
                <input
                  id="email-api-endpoint"
                  type="url"
                  className="ui-field"
                  value={form.apiEndpoint}
                  maxLength={2048}
                  required
                  placeholder="https://api.example.com/v1/email/send"
                  onChange={(event) => update({ apiEndpoint: event.target.value })}
                />
                <span className="ui-description mt-1.5 block">
                  HTTPS endpoint on port 443. Its hostname must be included in the server EGRESS_ALLOWED_HOSTS
                  allowlist.
                </span>
              </label>
              <label htmlFor="email-api-domain">
                Source / Domain
                <input
                  id="email-api-domain"
                  className="ui-field"
                  value={form.apiSourceDomain}
                  maxLength={253}
                  placeholder="mg.example.com"
                  onChange={(event) => update({ apiSourceDomain: event.target.value })}
                />
                <span className="ui-description mt-1.5 block">
                  Use {`{domain}`} in the endpoint URL to insert this value safely.
                </span>
              </label>
              <label htmlFor="email-api-header-key">
                Header key
                <input
                  id="email-api-header-key"
                  className="ui-field"
                  value={form.apiHeaderKey}
                  maxLength={100}
                  required
                    pattern="[!#$%&'*+.^_`|~0-9A-Za-z\-]+"
                  placeholder="Authorization"
                  onChange={(event) => update({ apiHeaderKey: event.target.value })}
                />
              </label>
              <label htmlFor="email-api-prefix">
                Authentication prefix
                <input
                  id="email-api-prefix"
                  className="ui-field"
                  value={form.apiAuthPrefix}
                  maxLength={40}
                  placeholder="Bearer"
                  onChange={(event) => update({ apiAuthPrefix: event.target.value })}
                />
                <span className="ui-description mt-1.5 block">
                  Default header: Authorization: Bearer &lt;key&gt;
                </span>
              </label>
              <label htmlFor="email-api-key" className="sm:col-span-2">
                Authentication Key
                <input
                  id="email-api-key"
                  type="password"
                  autoComplete="new-password"
                  spellCheck={false}
                  className="ui-field"
                  value={form.apiKey}
                  maxLength={4096}
                  required={!hasSavedApiKey}
                  placeholder={
                    hasSavedApiKey ? 'Secret API Key saved — leave blank to keep it' : 'Secret API Key'
                  }
                  onChange={(event) => update({ apiKey: event.target.value })}
                />
                <span className="ui-description mt-1.5 flex items-center gap-1.5">
                  <KeyRound className="h-3 w-3" /> Encrypted on the server. Saved keys are never displayed.
                </span>
              </label>
            </>
          )}
        </div>
        <div className="ui-actions justify-between">
          <span className="settings-save-state">
            <span className={dirty ? 'is-dirty' : ''} />
            {dirty ? 'Unsaved changes' : 'Saved delivery configuration'}
          </span>
          <div className="settings-action-buttons">
            {dirty && (
              <button
                type="button"
                className="ui-secondary"
                disabled={pending > 0}
                onClick={() => {
                  setForm(initialForm(emailConfig));
                  setDirty(false);
                  setMessage('');
                }}
              >
                <RotateCcw size={14} />
                Reset changes
              </button>
            )}
            <button type="submit" className="ui-primary" disabled={pending > 0 || !dirty}>
              {pending > 0 ? <LoaderCircle size={14} className="animate-spin" /> : <Save size={14} />}
              {pending > 0 ? 'Saving…' : 'Save email settings'}
            </button>
          </div>
        </div>
      </form>

      <form
        className="settings-test-card space-y-3"
        onSubmit={async (event) => {
          event.preventDefault();
          setMessage('');
          const result = await sendTestEmail(testEmail);
          if (result.success) setMessage('Test email queued. Check Email History for provider acceptance.');
        }}
      >
        <div>
          <h3 className="ui-card-title">Verify email delivery</h3>
          <p className="ui-description mt-1">Queue a test using your saved provider configuration.</p>
        </div>
        <label htmlFor="email-test-recipient" className="block">
          Test recipient
        </label>
        <div className="flex flex-col gap-3 sm:flex-row sm:items-start">
          <input
            id="email-test-recipient"
            aria-label="Test email recipient"
            type="email"
            className="ui-field flex-1"
            style={{ marginTop: 0 }}
            required
            maxLength={254}
            placeholder="you@your-domain.com"
            value={testEmail}
            onChange={(event) => setTestEmail(event.target.value)}
          />
          <button type="submit" className="ui-secondary shrink-0" disabled={pending > 0 || dirty}>
            <Send className="h-3.5 w-3.5" /> Queue test email
          </button>
        </div>
        <p className="ui-description">
          {dirty
            ? 'Save your delivery settings before sending a test.'
            : `Uses the saved ${methodName(emailConfig.provider)} configuration and background delivery queue.`}
        </p>
      </form>
      {message && (
        <p className="ui-success" role="status">
          {message}
        </p>
      )}
    </section>
  );
}
