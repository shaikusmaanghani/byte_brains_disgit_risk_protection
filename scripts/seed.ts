import { db } from '../server/db';
import { analyzeMobileApp, analyzeSocialCandidate } from '../src/services/detectionEngine';
import type { AppCandidateInput, Finding, SocialCandidateInput } from '../src/types';

const recent = new Date(Date.now() - 3 * 24 * 60 * 60 * 1000).toISOString();
const app = (
  appName: string,
  publisher: string,
  packageId: string,
  description: string,
  website?: string,
): AppCandidateInput => ({
  appName,
  publisher,
  developer: publisher,
  packageId,
  description,
  website,
  createdAt: recent,
  platform: 'google_play',
});
const social = (
  platform: SocialCandidateInput['platform'],
  username: string,
  profileName: string,
  biography: string,
  links: string[] = [],
): SocialCandidateInput => ({
  platform,
  username,
  profileName,
  biography,
  links,
  createdAt: recent,
});

const candidates: Array<
  { kind: 'app'; candidate: AppCandidateInput } |
  { kind: 'social'; candidate: SocialCandidateInput }
> = [
  { kind: 'app', candidate: app('Acme Mobile Banking', 'Rogue Apps LLC', 'com.demo.acme.clone', 'Official Acme banking. Log in to verify your account and claim a welcome reward.', 'https://acme-login-check.xyz') },
  { kind: 'app', candidate: app('Acme Finanical Banking', 'QuickSoft Studio', 'com.demo.acme.finanical', 'Manage your Acme Finanical account and check balances securely.') },
  { kind: 'app', candidate: app('Acme Financial Support', 'Global Help Apps', 'com.demo.acme.support', 'Urgent customer support, account verification, password reset, and emergency card help.') },
  { kind: 'app', candidate: app('Аcme Financial Wallet', 'Northstar Mobile', 'com.demo.acme.wallet', 'Acme Financial wallet access. Sign in to verify account and claim a giveaway.') },
  { kind: 'app', candidate: app('Acme Financial', 'Bright River Labs', 'com.demo.acme.financial', 'Acme Financial provides digital banking, checking accounts, savings, wealth advice, and mobile deposit services.', 'https://асmefinancial.example-login.net') },
  { kind: 'app', candidate: app('Acme Market News', 'MarketPulse Media', 'com.demo.marketpulse.acmenews', 'Independent company earnings coverage and financial market updates.') },
  { kind: 'app', candidate: app('Secure Acme Account Help', 'FastAssist Mobile', 'com.demo.fastassist.acme', 'Login to official support now. Urgent account verification and rewards.') },
  { kind: 'app', candidate: app('Daily Budget Planner', 'Pocket Ledger', 'com.demo.budget.planner', 'A personal spending diary with calendar and savings tips.') },
  { kind: 'app', candidate: app('Acme Savings Tips', 'Riverbend Publishing', 'com.demo.acme.savingsguide', 'Unofficial educational guide to saving and budgeting; not affiliated with Acme Financial.') },
  { kind: 'app', candidate: app('Acme QuickPay Rewards', 'Lucky Clover Software', 'com.demo.acme.quickpay', 'Claim your Acme QuickPay reward. Log in to verify your account now.', 'https://acme-rewards-claim.xyz') },
  { kind: 'social', candidate: social('x_twitter', 'acme_financiaI', 'Acme Financial Security', 'Official account. DM us for urgent support, account verification, and password reset.', ['https://t.me/acmehelpdesk']) },
  { kind: 'social', candidate: social('instagram', 'acme_financial_support', 'Acme Financial Help Desk', 'Customer support team. Claim rewards and sign in for urgent account verification.', ['https://acme-support-online.top']) },
  { kind: 'social', candidate: social('linkedin', 'acme-financial-careers', 'Acme Financial Careers', 'Independent job discussion group for people interested in financial services.') },
  { kind: 'social', candidate: social('facebook', 'acme_fan_club', 'Acme Financial Fan Club', 'Independent fan community sharing public company news. Not affiliated with Acme Financial.') },
  { kind: 'social', candidate: social('youtube', 'AcmeFinancialOfficialTV', 'Acme Financial Official Support', 'Contact support now for secure account help. Login to claim your giveaway.') },
  { kind: 'social', candidate: social('x_twitter', 'acmehelp_247', 'Acme Help 24/7', 'Acme Financial support team: verify account and reset credentials via direct message.') },
  { kind: 'social', candidate: social('instagram', 'acmefinancialnews', 'Acme Financial News', 'Independent news and financial education page discussing company announcements.') },
  { kind: 'social', candidate: social('facebook', 'acmebanking_reward', 'Acme Banking Rewards', 'Giveaway for Acme customers. Sign in and verify your account to claim a reward.', ['https://claim-acme-bonus.xyz']) },
];

let created = 0;
let refreshed = 0;
let excluded = 0;
for (const [index, item] of candidates.entries()) {
  const brand = db.getBrand();
  const analysis = item.kind === 'app'
    ? analyzeMobileApp(item.candidate, brand)
    : analyzeSocialCandidate(item.candidate, brand);
  if (analysis.isOfficialAsset) {
    excluded++;
    continue;
  }
  const identifier = item.kind === 'app'
    ? item.candidate.packageId
    : `@${item.candidate.username.replace(/^@/, '')}`;
  const url = item.kind === 'app'
    ? item.candidate.storeUrl || `https://play.google.com/store/apps/details?id=${item.candidate.packageId}`
    : item.candidate.profileUrl || `https://${item.candidate.platform}.example/${item.candidate.username}`;
  const detectedAt = new Date(Date.now() - index * 60 * 60 * 1000).toISOString();
  const finding: Finding = {
    id: `r2-demo-${String(index + 1).padStart(2, '0')}`,
    brandId: brand.id,
    assetType: item.kind === 'app' ? 'mobile_application' : 'social_profile',
    platform: item.candidate.platform,
    candidateName: item.kind === 'app' ? item.candidate.appName : item.candidate.profileName,
    identifier,
    url,
    publisherOrDeveloper: item.kind === 'app' ? item.candidate.publisher : `@${item.candidate.username}`,
    descriptionSnippet: item.kind === 'app' ? item.candidate.description : item.candidate.biography,
    riskScore: analysis.riskScore,
    riskLevel: analysis.riskLevel,
    classification: analysis.classification,
    confidence: analysis.confidence,
    status: index === 0 ? 'confirmed_threat' : 'new',
    firstSeen: detectedAt,
    lastSeen: detectedAt,
    notes: [],
    signals: analysis.signals.map((signal) => ({
      ...signal,
      pointsContributed: signal.pointsContributed ?? signal.score,
      signal: signal.signal || signal.type,
      reason: signal.reason || signal.explanation,
    })),
    radarBreakdown: analysis.radarBreakdown,
    recommendedAction: analysis.recommendedAction,
    summaryExplanation: analysis.summaryExplanation,
    matchedOfficialAsset: analysis.matchedOfficialAsset,
    candidatePayload: { ...item.candidate, demoSeed: true },
    isSimulated: true,
    investigationStatus: index === 0 ? 'Confirmed' : 'New',
    scoreBreakdown: analysis.scoreBreakdown || {},
    history: [{
      timestamp: detectedAt,
      actor: 'Demo seed',
      action: 'Detection created',
      toStatus: index === 0 ? 'Confirmed' : 'New',
      note: 'Simulated demonstration candidate evaluated by the existing detection engine.',
    }],
    isOfficialAsset: false,
  };
  const alreadyStored = db.getFindings().some(
    (stored) => stored.identifier === finding.identifier && stored.platform === finding.platform,
  );
  db.addFinding(finding);
  if (alreadyStored) refreshed++;
  else created++;
}

const official = db.getBrand().officialApps[0];
const officialResult = analyzeMobileApp({
  appName: official.appName,
  publisher: official.publisher,
  developer: official.developer,
  packageId: official.packageId,
  platform: official.platform,
  description: 'Registered official asset.',
}, db.getBrand());
if (officialResult.isOfficialAsset) excluded++;

console.log(`Processed ${candidates.length} clearly labelled demo candidates: created ${created} detections, refreshed ${refreshed} existing detections, and excluded ${excluded} official asset candidate(s).`);
