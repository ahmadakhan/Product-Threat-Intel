import type { EmailRecipient, SubscriptionTier } from '../src/types/index.ts';
import {
  FINDING_SUBSCRIPTIONS,
  NEWS_SUBSCRIPTION,
  DAILY_DIGEST_SUBSCRIPTION,
  recipientSubscriptions,
  subscribesToDailyDigest,
  subscribesToFindings,
  subscribesToNews,
} from '../src/types/index.ts';

/** One physical mailbox receives no more than one job from a queue pass.
 * When duplicate configurations exist, prefer the widest subscription; break
 * ties in favour of the Security team. The selected row owns the claim.
 */
export function uniqueEnabledEmailRecipients(recipients: readonly EmailRecipient[]): EmailRecipient[] {
  const byAddress = new Map<string, EmailRecipient>();
  // Widest finding tier wins; a recipient subscribed only to the news or digest
  // stream ranks below any findings subscription so it cannot shadow a mailbox
  // that also receives findings.
  const tierOrder: SubscriptionTier[] = ['ALL_SEVERITIES', 'CRITICAL_HIGH_ONLY', 'CISA_KEV_ONLY'];
  const tierRank = (recipient: EmailRecipient): number => {
    const tiers = recipientSubscriptions(recipient);
    return Math.max(1, ...tiers.map((tier) => 4 - tierOrder.indexOf(tier)).filter((rank) => rank > 0));
  };
  const groupRank = (recipient: EmailRecipient): number =>
    recipient.deliveryGroup === 'SECURITY_TEAM' ? 2 :
      recipient.deliveryGroup === 'EVERYONE' ? 0 : 1;
  for (const recipient of recipients) {
    if (!recipient.enabled) continue;
    const address = recipient.email?.trim().toLowerCase();
    if (!address) continue;
    const previous = byAddress.get(address);
    if (!previous || tierRank(recipient) > tierRank(previous) ||
      (tierRank(recipient) === tierRank(previous) &&
        (groupRank(recipient) > groupRank(previous) ||
          groupRank(recipient) === groupRank(previous) && recipient.id.localeCompare(previous.id) < 0))) {
      byAddress.set(address, recipient);
    }
  }
  return [...byAddress.values()].sort((a, b) =>
    a.email.toLowerCase().localeCompare(b.email.toLowerCase()) || a.id.localeCompare(b.id));
}

/**
 * Groups that receive the automated advisory and news streams.
 *
 * `ADMINISTRATORS` is included alongside the Security team: it is a separate
 * distribution list for senior stakeholders, but its members are subscribed to
 * the same advisory/news streams. A recipient with no group is a legacy record
 * and keeps receiving automatic delivery.
 */
export const AUTO_DELIVERY_GROUPS: Array<NonNullable<EmailRecipient['deliveryGroup']> | undefined> = [
  'SECURITY_TEAM',
  'ADMINISTRATORS',
  undefined,
];

/** True when the recipient is in a group that receives automated email. */
export const receivesAutomaticDelivery = (recipient: EmailRecipient): boolean =>
  recipient.deliveryGroup === 'SECURITY_TEAM' ||
  recipient.deliveryGroup === 'ADMINISTRATORS' ||
  recipient.deliveryGroup === undefined;

/**
 * Recipients eligible for consolidated security news.
 *
 * Membership is decided by subscription, not by group alone: a product owner in
 * the Administrators group who did not select NEWS never receives security
 * news, and the Security team no longer gets news implicitly. Selecting NEWS
 * for anyone who receives automated delivery opts them in.
 */
export const newsRecipients = (recipients: readonly EmailRecipient[]): EmailRecipient[] =>
  recipients.filter((recipient) => recipient.enabled && receivesAutomaticDelivery(recipient) && subscribesToNews(recipient));

/** Recipients eligible for the daily digest. */
export const dailyDigestRecipients = (recipients: readonly EmailRecipient[]): EmailRecipient[] =>
  recipients.filter((recipient) => recipient.enabled && subscribesToDailyDigest(recipient));

/** True when the recipient subscribed to any advisory findings tier. */
export const receivesFindings = (recipient: EmailRecipient): boolean => subscribesToFindings(recipient);

export { FINDING_SUBSCRIPTIONS, NEWS_SUBSCRIPTION, DAILY_DIGEST_SUBSCRIPTION };
export { recipientSubscriptions, subscribesToNews, subscribesToDailyDigest, subscribesToFindings };
export type { SubscriptionTier };
