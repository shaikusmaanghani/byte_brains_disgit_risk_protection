import assert from 'node:assert';
import {
  analyzeMobileApp,
  analyzeSocialCandidate,
  detectAndNormalizeHomoglyphs,
  damerauLevenshtein,
  stringSimilarity,
} from '../src/services/detectionEngine';
import { BrandProfile, AppCandidateInput, SocialCandidateInput } from '../src/types';

// Mock Brand Profile
const mockBrand: BrandProfile = {
  id: 'brand-acme',
  name: 'Acme Financial',
  logoUrl: 'https://example.com/acme_logo.png',
  aliases: ['Acme Bank', 'Acme FinTech', 'Acme'],
  officialDomains: ['acmefinancial.com', 'acmebank.com'],
  brandKeywords: ['banking', 'checking', 'wealth', 'investments', 'acme safe', 'secure money'],
  productNames: ['Acme Mobile Banking', 'Acme Wealth Portal'],
  supportEmailDomains: ['acmefinancial.com'],
  officialWebsite: 'https://www.acmefinancial.com',
  companyDescription: 'Official Acme Financial secure digital mobile banking, checking, and wealth management platform.',
  knownPublishers: ['Acme Financial Technologies', 'Acme Corp Labs'],
  knownDevelopers: ['Acme Financial Technologies Dev Team'],
  officialApps: [
    {
      id: 'app-acme-mobile',
      appName: 'Acme Mobile Banking',
      packageId: 'com.acme.mobilebanking',
      platform: 'google_play',
      developer: 'Acme Financial Technologies Dev Team',
      publisher: 'Acme Financial Technologies',
      storeUrl: 'https://play.google.com/store/apps/details?id=com.acme.mobilebanking',
      version: '4.2.0',
      category: 'Finance',
      iconUrl: 'https://example.com/acme_logo.png',
      officialDomain: 'acmefinancial.com',
    },
  ],
  officialSocialAccounts: [
    {
      id: 'social-acme-x',
      platform: 'x_twitter',
      handle: 'AcmeFinancial',
      profileName: 'Acme Financial Official',
      profileUrl: 'https://x.com/AcmeFinancial',
      verified: true,
      avatarUrl: 'https://example.com/acme_logo.png',
    },
  ],
  createdAt: '2026-01-01T00:00:00Z',
  updatedAt: '2026-01-01T00:00:00Z',
};

console.log('🧪 Running SentinelShield Threat Detection Engine Test Suite...\n');

// 1. Official App Exclusion Test
{
  const officialCandidate: AppCandidateInput = {
    appName: 'Acme Mobile Banking',
    developer: 'Acme Financial Technologies Dev Team',
    publisher: 'Acme Financial Technologies',
    packageId: 'com.acme.mobilebanking',
    platform: 'google_play',
    description: 'Official banking app for Acme Financial accounts.',
  };

  const result = analyzeMobileApp(officialCandidate, mockBrand);
  assert.strictEqual(result.isOfficialAsset, true, 'Official app must be marked isOfficialAsset=true');
  assert.strictEqual(result.riskScore, 0, 'Official app risk score must be 0');
  assert.strictEqual(result.riskLevel, 'informational', 'Official app risk level must be informational');
  assert.strictEqual(result.classification, 'official', 'Official app classification must be official');
  console.log('✅ Test 1 Passed: Official application successfully recognized and excluded from threats.');
}

// 2. CRITICAL TEST: Publisher Mismatch (Same Name, Unauthorized Publisher)
{
  const rogueCandidate: AppCandidateInput = {
    appName: 'Acme Mobile Banking',
    developer: 'Rogue Apps LLC',
    publisher: 'Rogue Apps LLC',
    packageId: 'com.fake.acme.bank',
    platform: 'google_play',
    description: 'Official Acme secure banking application. Verify your account and receive rewards.',
    website: 'https://phishing-acme-login.biz',
  };

  const result = analyzeMobileApp(rogueCandidate, mockBrand);
  assert.strictEqual(result.isOfficialAsset, false, 'Candidate with unauthorized publisher MUST NOT be marked official');
  assert.ok(result.riskScore >= 80, `Expected risk score >= 80 for rogue app, got ${result.riskScore}`);
  assert.strictEqual(result.riskLevel, 'critical', 'Risk level must be critical for rogue app clone');
  
  const pubSignal = result.signals.find((s) => s.type === 'publisher_mismatch');
  assert.ok(pubSignal, 'Publisher mismatch signal MUST be generated');
  assert.strictEqual(pubSignal.score, 20, 'Publisher mismatch must carry 20 points');

  const pkgSignal = result.signals.find((s) => s.type === 'package_mismatch');
  assert.ok(pkgSignal, 'Package mismatch signal must be generated');

  const domainSignal = result.signals.find((s) => s.type === 'domain_mismatch');
  assert.ok(domainSignal, 'Domain mismatch signal must be generated');

  console.log(`✅ Test 2 Passed: Rogue App clone flagged with risk score ${result.riskScore}/100 [CRITICAL] and strong publisher mismatch signal.`);
}

// 3. Look-Alike Spelling & Transposition (e.g. Acme Finanical)
{
  const typoCandidate: AppCandidateInput = {
    appName: 'Acme Finanical Banking',
    developer: 'QuickMobile Soft',
    publisher: 'QuickMobile Soft',
    packageId: 'com.quickmobile.banking',
    platform: 'google_play',
    description: 'Fast mobile banking tools.',
  };

  const result = analyzeMobileApp(typoCandidate, mockBrand);
  assert.ok(result.riskScore >= 35, `Transposition should trigger risk >= 35, got ${result.riskScore}`);
  const nameSignal = result.signals.find((s) => s.type === 'name_similarity');
  assert.ok(nameSignal, 'Name similarity should catch transposition');
  console.log(`✅ Test 3 Passed: Transposition "Finanical" caught with score ${result.riskScore}.`);
}

// 4. Added Words (Acme Financial Support)
{
  const addedWordsCandidate: AppCandidateInput = {
    appName: 'Acme Financial Support',
    developer: 'Global Tech Support',
    publisher: 'Global Tech Support',
    packageId: 'com.global.acmesupport',
    platform: 'google_play',
    description: 'Urgent customer support and account verification for Acme Financial users.',
  };

  const result = analyzeMobileApp(addedWordsCandidate, mockBrand);
  assert.ok(result.riskScore >= 60, `Added words with phishing lures should be high risk, got ${result.riskScore}`);
  const kwSignal = result.signals.find((s) => s.type === 'suspicious_keywords');
  assert.ok(kwSignal, 'Suspicious keywords signal must trigger');
  console.log(`✅ Test 4 Passed: Added words "Acme Financial Support" flagged with score ${result.riskScore}.`);
}

// 5. Homoglyph Detection (Cyrillic & Confusable characters)
{
  // "AcmeFinanciaI" (Latin uppercase I instead of lowercase l)
  const homoglyph1 = detectAndNormalizeHomoglyphs('AcmeFinanciaI');
  assert.strictEqual(homoglyph1.hasHomoglyphs, true, 'Should detect uppercase I as confusable l');
  assert.strictEqual(homoglyph1.normalized, 'AcmeFinancial');

  // Cyrillic 'а' (\u0430) and 'е' (\u0435)
  const cyrillicName = 'Аcmе Finаnciаl'; // contains Cyrillic characters
  const homoglyph2 = detectAndNormalizeHomoglyphs(cyrillicName);
  assert.strictEqual(homoglyph2.hasHomoglyphs, true, 'Should detect Cyrillic look-alikes');
  console.log('✅ Test 5 Passed: Homoglyph detection handles Cyrillic and confusable uppercase I.');
}

// 6. Social Account Official Exclusion
{
  const officialSocial: SocialCandidateInput = {
    platform: 'x_twitter',
    username: 'AcmeFinancial',
    profileName: 'Acme Financial Official',
    biography: 'Official account of Acme Financial.',
    verified: true,
  };

  const result = analyzeSocialCandidate(officialSocial, mockBrand);
  assert.strictEqual(result.isOfficialAsset, true, 'Exact official handle must be excluded');
  assert.strictEqual(result.riskScore, 0, 'Official social score must be 0');
  console.log('✅ Test 6 Passed: Official social account correctly excluded.');
}

// 7. Impersonating Social Account (@acme_financial_support with phishing lures)
{
  const fakeSocial: SocialCandidateInput = {
    platform: 'x_twitter',
    username: 'acme_financial_support',
    profileName: 'Acme Financial Support 24/7',
    biography: 'Official 24/7 customer support. Urgent verification needed. Claim reward and reset credentials here.',
    links: ['https://claim-acme-support.xyz'],
    verified: false,
  };

  const result = analyzeSocialCandidate(fakeSocial, mockBrand);
  assert.strictEqual(result.isOfficialAsset, false);
  assert.ok(result.riskScore >= 70, `Fake social profile should have risk >= 70, got ${result.riskScore}`);
  assert.strictEqual(result.riskLevel, 'critical');
  console.log(`✅ Test 7 Passed: Fake social account detected with risk score ${result.riskScore}/100.`);
}

// 8. False Positive Safeguard: Unrelated App (e.g. Weather Forecast)
{
  const unrelatedApp: AppCandidateInput = {
    appName: 'SunnyDay Weather Forecast',
    developer: 'Sky Met Systems',
    publisher: 'Sky Met Systems',
    packageId: 'com.skymet.weather',
    platform: 'google_play',
    description: 'Accurate 7-day weather radar and precipitation forecasts.',
  };

  const result = analyzeMobileApp(unrelatedApp, mockBrand);
  assert.strictEqual(result.isOfficialAsset, false);
  assert.ok(result.riskScore <= 15, `Unrelated app score must be <= 15, got ${result.riskScore}`);
  assert.strictEqual(result.riskLevel, 'informational');
  console.log(`✅ Test 8 Passed: Unrelated application safely evaluated without false alarms (Score: ${result.riskScore}).`);
}

console.log('\n🎉 ALL 8 DETECTION ENGINE TESTS PASSED PERFECTLY!\n');
