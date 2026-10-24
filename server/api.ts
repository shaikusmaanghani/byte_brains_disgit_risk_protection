import { Router } from 'express';
import type { Request, Response } from 'express';
import { db } from './db.js';
import {
  analyzeMobileApp,
  analyzeSocialCandidate,
} from '../src/services/detectionEngine.js';
import type {
  AppCandidateInput,
  SocialCandidateInput,
  Finding,
  ThreatGraphNode,
  ThreatGraphLink,
} from '../src/types/index.js';
import { answerAnalystQuestion, getDetection } from '../src/services/analystAssistant.js';
import { draftTakedownReport } from '../src/services/takedownReport.js';
import { appendHistory, transitionFinding } from '../src/services/investigation.js';
import { AuthenticatedRequest, createDemoSession, requireSession, revokeSession } from './auth.js';
export const apiRouter = Router();

// Middleware: Basic request logger & header check
apiRouter.use((req, res, next) => {
  res.setHeader('X-Sentinel-Engine-Version', '3.8.4');
  res.setHeader('X-Sentinel-Environment', 'Production-Ready SOC');
  next();
});

// GET /api/health
apiRouter.get('/health', (req: Request, res: Response) => {
  const health = db.getSystemHealth();
  res.json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    service: 'SentinelShield Digital Risk Protection API',
    version: '3.8.4',
    diagnostics: health,
  });
});

// POST /api/auth/login
apiRouter.post('/auth/login', (req: Request, res: Response) => {
  const { email, password } = req.body as { email?: string; password?: string };
  if (!email || !password) {
    res.status(400).json({ error: 'Email and password are required.' });
    return;
  }
  const session = createDemoSession(email, password, db.getUsers());
  if (!session) {
    res.status(401).json({ error: 'Invalid demo credentials.' });
    return;
  }
  res.json(session);
});

apiRouter.get('/auth/me', requireSession, (req: Request, res: Response) => {
  res.json((req as AuthenticatedRequest).user);
});

apiRouter.post('/auth/logout', requireSession, (req: Request, res: Response) => {
  const token = (req as AuthenticatedRequest).sessionToken;
  if (token) revokeSession(token);
  res.json({ success: true });
});

apiRouter.use(requireSession);

// GET /api/profile
apiRouter.get('/profile', (req: Request, res: Response) => {
  res.json(db.getBrand());
});

// PUT /api/profile
apiRouter.put('/profile', (req: Request, res: Response) => {
  const updated = db.updateBrand(req.body);
  res.json(updated);
});

// GET /api/social/findings
apiRouter.get('/social/findings', (req: Request, res: Response) => {
  const all = db.getFindings();
  const filtered = all.filter((f) => f.assetType === 'social_profile');
  res.json(filtered);
});

// GET /api/apps/findings
apiRouter.get('/apps/findings', (req: Request, res: Response) => {
  const all = db.getFindings();
  const filtered = all.filter((f) => f.assetType === 'mobile_application');
  res.json(filtered);
});

// GET /api/findings
apiRouter.get('/findings', (req: Request, res: Response) => {
  let list = db.getFindings();
  const { search, platform, assetType, risk, status, sort } = req.query;
  if (search && typeof search === 'string') {
    const q = search.toLowerCase();
    list = list.filter(
      (f) =>
        f.candidateName.toLowerCase().includes(q) ||
        f.identifier.toLowerCase().includes(q) ||
        (f.publisherOrDeveloper && f.publisherOrDeveloper.toLowerCase().includes(q)) ||
        (f.descriptionSnippet && f.descriptionSnippet.toLowerCase().includes(q))
    );
  }

  if (platform && typeof platform === 'string' && platform !== 'all') {
    list = list.filter((f) => f.platform === platform);
  }

  if (assetType && typeof assetType === 'string' && assetType !== 'all') {
    list = list.filter((f) => f.assetType === assetType);
  }

  if (risk && typeof risk === 'string' && risk !== 'all') {
    list = list.filter((f) => f.riskLevel === risk);
  }

  if (status && typeof status === 'string' && status !== 'all') {
    list = list.filter((f) => f.status === status);
  }

  if (sort === 'risk_asc') {
    list.sort((a, b) => a.riskScore - b.riskScore);
  } else if (sort === 'oldest') {
    list.sort((a, b) => new Date(a.firstSeen).getTime() - new Date(b.firstSeen).getTime());
  } else if (sort === 'newest') {
    list.sort((a, b) => new Date(b.firstSeen).getTime() - new Date(a.firstSeen).getTime());
  } else {
    // default: highest risk first
    list.sort((a, b) => b.riskScore - a.riskScore || new Date(b.lastSeen).getTime() - new Date(a.lastSeen).getTime());
  }

  res.json(list);
});

// GET /api/findings/:id
apiRouter.get('/findings/:id', (req: Request, res: Response) => {
  const item = db.getFindingById(req.params.id);
  if (!item) {
    res.status(404).json({ error: 'Finding not found' });
    return;
  }
  res.json(item);
});

// POST /api/findings
apiRouter.post('/findings', (req: Request, res: Response) => {
  const brand = db.getBrand();
  const candidate = req.body;
  const isApp = candidate.assetType === 'mobile_application' || candidate.appName;

  let analysis;
  if (isApp) {
    analysis = analyzeMobileApp(candidate, brand);
  } else {
    analysis = analyzeSocialCandidate(candidate, brand);
  }

  if (analysis.isOfficialAsset) {
    res.status(200).json({
      officialExcluded: true,
      message: 'Official asset excluded from threat findings.',
      analysis,
    });
    return;
  }

  const newFinding: Finding = {
    id: `find-man-${Date.now()}-${Math.random().toString(16).slice(2, 8)}`,
    brandId: brand.id,
    assetType: isApp ? 'mobile_application' : 'social_profile',
    platform: candidate.platform || (isApp ? 'google_play' : 'x_twitter'),
    candidateName: candidate.appName || candidate.profileName || candidate.username,
    identifier: candidate.packageId || (candidate.username ? `@${candidate.username.replace(/^@/, '')}` : 'unknown'),
    url: candidate.storeUrl || candidate.profileUrl || candidate.url || 'https://google.com',
    publisherOrDeveloper: candidate.publisher || candidate.developer || candidate.username,
    descriptionSnippet: candidate.description || candidate.biography,
    riskScore: analysis.riskScore,
    riskLevel: analysis.riskLevel,
    classification: analysis.classification,
    confidence: analysis.confidence,
    status: 'new',
    firstSeen: new Date().toISOString(),
    lastSeen: new Date().toISOString(),
    notes: [],
    signals: analysis.signals,
    radarBreakdown: analysis.radarBreakdown,
    recommendedAction: analysis.recommendedAction,
    summaryExplanation: analysis.summaryExplanation,
    matchedOfficialAsset: analysis.matchedOfficialAsset,
    candidatePayload: candidate,
    isSimulated: false,
    investigationStatus: 'New',
    scoreBreakdown: analysis.scoreBreakdown || {},
    history: [{
      timestamp: new Date().toISOString(),
      actor: (req as AuthenticatedRequest).user?.name || 'System',
      action: 'Detection created',
      toStatus: 'New',
      note: 'Candidate evaluated by the deterministic scoring engine.',
    }],
    isOfficialAsset: false,
  };

  const saved = db.addFinding(newFinding);
  res.status(201).json(saved);
});

// PATCH /api/findings/:id
apiRouter.patch('/findings/:id', (req: Request, res: Response) => {
  const existing = db.getFindingById(req.params.id);
  if (!existing) {
    res.status(404).json({ error: 'Finding not found' });
    return;
  }

  const actor = (req as AuthenticatedRequest).user?.name || 'Analyst';
  const updates: Record<string, any> = {};
  if (typeof req.body?.assignedAnalyst === 'string') updates.assignedAnalyst = req.body.assignedAnalyst;
  if (typeof req.body?.status === 'string') updates.status = req.body.status;
  if (req.body?.newNote && typeof req.body.newNote.content === 'string') updates.newNote = req.body.newNote;
  let nextFinding = existing;
  const legacyToInvestigation: Record<string, import('../src/types/index.js').InvestigationStatus> = {
    new: 'New',
    investigating: 'Under Review',
    confirmed_threat: 'Confirmed',
    false_positive: 'False Positive',
    resolved: 'Closed',
    dismissed: 'Closed',
  };
  if (updates.status && updates.status !== existing.status) {
    const nextStatus = legacyToInvestigation[updates.status];
    if (!nextStatus) {
      res.status(400).json({ error: 'Unsupported investigation status.' });
      return;
    }
    try {
      nextFinding = transitionFinding(
        existing,
        nextStatus,
        actor,
        updates.newNote?.content || `Status changed to ${nextStatus}.`,
      );
    } catch (error) {
      res.status(409).json({ error: error instanceof Error ? error.message : 'Invalid status transition.' });
      return;
    }
    delete updates.status;
  }
  // If notes added
  if (updates.newNote) {
    const note = {
      id: `note-${Date.now()}`,
      authorName: actor,
      authorEmail: (req as AuthenticatedRequest).user?.email || '',
      createdAt: new Date().toISOString(),
      content: updates.newNote.content,
      actionTaken: updates.newNote.actionTaken,
    };
    updates.notes = [...(nextFinding.notes || []), note];
    nextFinding = appendHistory(
      nextFinding,
      actor,
      'Analyst note added',
      updates.newNote.content,
    );
    delete updates.newNote;
  }

  const updated = db.updateFinding(req.params.id, { ...nextFinding, ...updates });
  res.json(updated);
});

apiRouter.post('/findings/:id/investigate', (req: Request, res: Response) => {
  const finding = db.getFindingById(req.params.id);
  if (!finding) {
    res.status(404).json({ error: 'Finding not found.' });
    return;
  }
  const { status, note } = req.body as { status?: import('../src/types/index.js').InvestigationStatus; note?: string };
  if (!status || !note?.trim()) {
    res.status(400).json({ error: 'A valid target status and reason are required.' });
    return;
  }
  try {
    const updated = transitionFinding(finding, status, (req as AuthenticatedRequest).user!.name, note);
    res.json(db.updateFinding(finding.id, updated));
  } catch (error) {
    res.status(409).json({ error: error instanceof Error ? error.message : 'Invalid status transition.' });
  }
});

apiRouter.post('/findings/:id/report', (req: Request, res: Response) => {
  const finding = db.getFindingById(req.params.id);
  if (!finding) {
    res.status(404).json({ error: 'Finding not found.' });
    return;
  }
  try {
    const actor = (req as AuthenticatedRequest).user!.name;
    const report = draftTakedownReport(finding, actor);
    db.updateFinding(finding.id, appendHistory(finding, actor, 'Report drafted', 'Draft takedown report generated.'));
    res.json({ report });
  } catch (error) {
    res.status(409).json({ error: error instanceof Error ? error.message : 'Could not draft report.' });
  }
});

apiRouter.get('/alerts', (req: Request, res: Response) => {
  res.json(db.getAlerts());
});

apiRouter.post('/alerts/:id/read', (req: Request, res: Response) => {
  const alert = db.markAlertRead(req.params.id);
  if (!alert) {
    res.status(404).json({ error: 'Alert not found.' });
    return;
  }
  res.json(alert);
});

apiRouter.post('/assistant/chat', (req: Request, res: Response) => {
  const question = typeof req.body?.question === 'string' ? req.body.question.trim() : '';
  if (!question) {
    res.status(400).json({ error: 'A question is required.' });
    return;
  }
  const findings = db.getFindings();
  const actor = (req as AuthenticatedRequest).user!.name;
  const answer = answerAnalystQuestion(question, findings, actor);
  if (/draft|takedown/i.test(question) && answer.startsWith('# Platform review request')) {
    const finding = getDetection(findings, question);
    if (finding) {
      db.updateFinding(finding.id, appendHistory(finding, actor, 'Report drafted', 'Draft takedown report generated via the offline assistant.'));
    }
  }
  res.json({ answer });
});

// DELETE /api/findings/:id
apiRouter.delete('/findings/:id', (req: Request, res: Response) => {
  const success = db.deleteFinding(req.params.id);
  if (!success) {
    res.status(404).json({ error: 'Finding not found' });
    return;
  }
  res.json({ message: 'Finding removed successfully' });
});

// POST /api/analyze/app
apiRouter.post('/analyze/app', (req: Request, res: Response) => {
  const brand = db.getBrand();
  const candidate: AppCandidateInput = req.body;
  const analysis = analyzeMobileApp(candidate, brand);
  res.json(analysis);
});

// POST /api/analyze/social
apiRouter.post('/analyze/social', (req: Request, res: Response) => {
  const brand = db.getBrand();
  const candidate: SocialCandidateInput = req.body;
  const analysis = analyzeSocialCandidate(candidate, brand);
  res.json(analysis);
});

// POST /api/analyze (universal)
apiRouter.post('/analyze', (req: Request, res: Response) => {
  const brand = db.getBrand();
  const candidate = req.body;
  if (candidate.appName || candidate.packageId || candidate.assetType === 'mobile_application') {
    const analysis = analyzeMobileApp(candidate as AppCandidateInput, brand);
    res.json(analysis);
  } else {
    const analysis = analyzeSocialCandidate(candidate as SocialCandidateInput, brand);
    res.json(analysis);
  }
});

// POST /api/monitoring/run
apiRouter.post('/monitoring/run', (req: Request, res: Response) => {
  const brand = db.getBrand();

  // Synthetic pool of candidate entities representing continuous external surface ingestion
  const simulatedBatch = [
    {
      type: 'app' as const,
      candidate: {
        appName: 'Acme Mobile Banking',
        developer: 'Rogue Apps LLC',
        publisher: 'Rogue Apps LLC',
        packageId: 'com.fake.acme.bank',
        platform: 'google_play' as const,
        description:
          'Official Acme secure banking application. Verify your account and receive rewards. Fast balance lookups.',
        website: 'https://verify-acme-auth.top',
        permissions: ['android.permission.READ_SMS', 'android.permission.RECEIVE_SMS'],
      },
    },
    {
      type: 'app' as const,
      candidate: {
        appName: 'Acme Finanical Banking',
        developer: 'Shadow Soft Labs',
        publisher: 'Shadow Soft Labs',
        packageId: 'com.shadowsoft.acme',
        platform: 'google_play' as const,
        description: 'Instant mobile credit line and banking check deposit tool for Acme Finanical customers.',
      },
    },
    {
      type: 'app' as const,
      candidate: {
        appName: 'Acme Financial Support Mobile',
        developer: 'FastAssist Mobile',
        publisher: 'FastAssist Mobile',
        packageId: 'com.fastassist.acmesupport',
        platform: 'google_play' as const,
        description: 'Urgent customer support, account verification, and emergency card hotline.',
        website: 'https://acme-support-live.xyz',
      },
    },
    {
      type: 'social' as const,
      candidate: {
        platform: 'x_twitter' as const,
        username: 'acme_financiaI',
        profileName: 'Acme Financial Security',
        biography: 'Official security desk of Acme Financial. DM for account verification and security alert unlocks.',
        links: ['https://claim-acme-security.biz'],
        verified: false,
      },
    },
    {
      type: 'social' as const,
      candidate: {
        platform: 'instagram' as const,
        username: 'acme_financial_helpdesk',
        profileName: 'Acme Financial Help',
        biography: 'Direct assistance for Acme banking customers. Account verification, urgent support, and bonuses.',
        links: ['https://acme-helpdesk.link'],
        verified: false,
      },
    },
  ];

  let addedCount = 0;
  for (const item of simulatedBatch) {
    if (item.type === 'app') {
      const analysis = analyzeMobileApp(item.candidate, brand);
      if (!analysis.isOfficialAsset) {
        db.addFinding({
          id: `find-scan-${Date.now()}-${Math.floor(Math.random() * 1000)}`,
          brandId: brand.id,
          assetType: 'mobile_application',
          platform: item.candidate.platform,
          candidateName: item.candidate.appName,
          identifier: item.candidate.packageId,
          url: `https://play.google.com/store/apps/details?id=${item.candidate.packageId}`,
          publisherOrDeveloper: item.candidate.publisher,
          descriptionSnippet: item.candidate.description,
          riskScore: analysis.riskScore,
          riskLevel: analysis.riskLevel,
          classification: analysis.classification,
          confidence: analysis.confidence,
          status: 'new',
          firstSeen: new Date().toISOString(),
          lastSeen: new Date().toISOString(),
          notes: [],
          signals: analysis.signals,
          radarBreakdown: analysis.radarBreakdown,
          recommendedAction: analysis.recommendedAction,
          summaryExplanation: analysis.summaryExplanation,
          matchedOfficialAsset: analysis.matchedOfficialAsset,
          candidatePayload: item.candidate,
          isSimulated: true,
        });
        addedCount++;
      }
    } else {
      const analysis = analyzeSocialCandidate(item.candidate, brand);
      if (!analysis.isOfficialAsset) {
        db.addFinding({
          id: `find-scan-${Date.now()}-${Math.floor(Math.random() * 1000)}`,
          brandId: brand.id,
          assetType: 'social_profile',
          platform: item.candidate.platform,
          candidateName: item.candidate.profileName,
          identifier: `@${item.candidate.username}`,
          url: `https://${item.candidate.platform}.com/${item.candidate.username}`,
          publisherOrDeveloper: `@${item.candidate.username}`,
          descriptionSnippet: item.candidate.biography,
          riskScore: analysis.riskScore,
          riskLevel: analysis.riskLevel,
          classification: analysis.classification,
          confidence: analysis.confidence,
          status: 'new',
          firstSeen: new Date().toISOString(),
          lastSeen: new Date().toISOString(),
          notes: [],
          signals: analysis.signals,
          radarBreakdown: analysis.radarBreakdown,
          recommendedAction: analysis.recommendedAction,
          summaryExplanation: analysis.summaryExplanation,
          matchedOfficialAsset: analysis.matchedOfficialAsset,
          candidatePayload: item.candidate,
          isSimulated: true,
        });
        addedCount++;
      }
    }
  }

  const scanStats = db.recordMonitoringScan(addedCount);

  res.json({
    success: true,
    message: 'Monitoring scan completed successfully across all registered data sources.',
    scannedSources: db.getSources().length,
    threatsIdentified: addedCount,
    lastScanTime: scanStats.lastScanTime,
    totalScansCount: scanStats.totalScansCount,
  });
});

// GET /api/analytics/overview
apiRouter.get('/analytics/overview', (req: Request, res: Response) => {
  const brand = db.getBrand();
  const findings = db.getFindings();

  const totalMonitoredAssets =
    brand.officialApps.length +
    brand.officialSocialAccounts.length +
    brand.officialDomains.length;

  const socialAssetsMonitored = brand.officialSocialAccounts.length;
  const applicationsMonitored = brand.officialApps.length;

  const activeThreats = findings.filter(
    (f) => f.status === 'new' || f.status === 'investigating' || f.status === 'confirmed_threat'
  );

  const criticalThreats = activeThreats.filter((f) => f.riskLevel === 'critical').length;
  const highRiskThreats = activeThreats.filter((f) => f.riskLevel === 'high').length;
  const mediumRiskThreats = activeThreats.filter((f) => f.riskLevel === 'medium').length;
  const lowRiskThreats = activeThreats.filter((f) => f.riskLevel === 'low').length;
  const resolvedThreats = findings.filter((f) => f.status === 'resolved' || f.status === 'dismissed').length;
  const newDetections = findings.filter((f) => f.status === 'new').length;

  const oneDayAgo = new Date(Date.now() - 24 * 60 * 60 * 1000).getTime();
  const sevenDaysAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).getTime();

  const detectedLast24h = findings.filter(
    (f) => new Date(f.firstSeen).getTime() >= oneDayAgo
  ).length;

  const detectedLast7d = findings.filter(
    (f) => new Date(f.firstSeen).getTime() >= sevenDaysAgo
  ).length;

  // Determine overall Threat Level
  let overallThreatLevel: 'Critical' | 'High' | 'Medium' | 'Low' | 'Informational' = 'Informational';
  if (criticalThreats >= 2) overallThreatLevel = 'Critical';
  else if (criticalThreats === 1 || highRiskThreats >= 2) overallThreatLevel = 'High';
  else if (highRiskThreats === 1 || mediumRiskThreats >= 2) overallThreatLevel = 'Medium';
  else if (mediumRiskThreats === 1 || lowRiskThreats > 0) overallThreatLevel = 'Low';

  res.json({
    totalMonitoredAssets,
    socialAssetsMonitored,
    applicationsMonitored,
    activeThreats: activeThreats.length,
    criticalThreats,
    highRiskThreats,
    mediumRiskThreats,
    lowRiskThreats,
    resolvedThreats,
    newDetections,
    detectedLast24h,
    detectedLast7d,
    overallThreatLevel,
    averageRiskScore:
      findings.length > 0
        ? Math.round(findings.reduce((acc, f) => acc + f.riskScore, 0) / findings.length)
        : 0,
  });
});

// GET /api/analytics/trends
apiRouter.get('/analytics/trends', (req: Request, res: Response) => {
  const findings = db.getFindings();

  // Timeline series (past 7 days)
  const days = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];
  const threatsOverTime = days.map((day, idx) => ({
    day,
    socialThreats: Math.max(1, (idx * 2 + 1) % 6),
    appThreats: Math.max(1, (idx * 3 + 2) % 5),
    total: Math.max(2, (idx * 2 + idx * 3 + 3) % 9),
  }));

  // Risk distribution
  const riskDistribution = [
    { name: 'Critical (80-100)', count: findings.filter((f) => f.riskLevel === 'critical').length, color: '#f43f5e' },
    { name: 'High (60-79)', count: findings.filter((f) => f.riskLevel === 'high').length, color: '#f97316' },
    { name: 'Medium (35-59)', count: findings.filter((f) => f.riskLevel === 'medium').length, color: '#eab308' },
    { name: 'Low (15-34)', count: findings.filter((f) => f.riskLevel === 'low').length, color: '#06b6d4' },
    { name: 'Informational (0-14)', count: findings.filter((f) => f.riskLevel === 'informational').length, color: '#10b981' },
  ];

  // Detection signal distribution
  const signalCounts: Record<string, number> = {
    'Name Similarity': 0,
    'Publisher Mismatch': 0,
    'Developer Mismatch': 0,
    'Description Mimicry': 0,
    'Package ID Mismatch': 0,
    'Homoglyph Substitution': 0,
    'Unauthorized Domain': 0,
    'Phishing Keywords': 0,
  };

  for (const f of findings) {
    for (const s of f.signals) {
      if (s.type === 'name_similarity' || s.type === 'username_similarity') signalCounts['Name Similarity']++;
      if (s.type === 'publisher_mismatch') signalCounts['Publisher Mismatch']++;
      if (s.type === 'developer_mismatch') signalCounts['Developer Mismatch']++;
      if (s.type === 'description_similarity') signalCounts['Description Mimicry']++;
      if (s.type === 'package_mismatch') signalCounts['Package ID Mismatch']++;
      if (s.type === 'homoglyph_detected') signalCounts['Homoglyph Substitution']++;
      if (s.type === 'domain_mismatch') signalCounts['Unauthorized Domain']++;
      if (s.type === 'suspicious_keywords') signalCounts['Phishing Keywords']++;
    }
  }

  const signalDistribution = Object.entries(signalCounts).map(([name, count]) => ({
    name,
    count,
  }));

  // Platform distribution
  const platformCounts: Record<string, number> = {};
  for (const f of findings) {
    platformCounts[f.platform] = (platformCounts[f.platform] || 0) + 1;
  }
  const threatSourceDistribution = Object.entries(platformCounts).map(([platform, count]) => ({
    platform: platform.replace(/_/g, ' ').toUpperCase(),
    count,
  }));

  // Impersonation patterns
  const topPatterns = [
    { pattern: 'Publisher Mismatch Clone', count: 9, description: 'Identical app name uploaded by unauthorized rogue publisher entity' },
    { pattern: 'Look-Alike Typo Squatting', count: 7, description: 'Transposed characters (e.g. Acme Finanical instead of Financial)' },
    { pattern: 'Phishing Support Channels', count: 6, description: 'Added terms like Support / Care / Help with credential theft lures' },
    { pattern: 'Homoglyph Character Spoofing', count: 4, description: 'Cyrillic or Latin uppercase I replacing lowercase l' },
    { pattern: 'Unauthorized Giveaway Handles', count: 3, description: 'Promising prizes or crypto rewards in exchange for wallet auth' },
  ];

  res.json({
    threatsOverTime,
    riskDistribution,
    signalDistribution,
    threatSourceDistribution,
    topPatterns,
  });
});

// GET /api/sources
apiRouter.get('/sources', (req: Request, res: Response) => {
  res.json(db.getSources());
});

// POST /api/sources
apiRouter.post('/sources', (req: Request, res: Response) => {
  const { id, ...updates } = req.body;
  const updated = db.updateSource(id, updates);
  if (!updated) {
    res.status(404).json({ error: 'Source not found' });
    return;
  }
  res.json(updated);
});

// GET /api/watchlists
apiRouter.get('/watchlists', (req: Request, res: Response) => {
  res.json(db.getWatchlists());
});

// POST /api/watchlists
apiRouter.post('/watchlists', (req: Request, res: Response) => {
  const newRule = {
    id: `w-${Date.now()}`,
    name: req.body.name,
    targetType: req.body.targetType,
    pattern: req.body.pattern,
    severity: req.body.severity || 'high',
    enabled: true,
    hitsCount: 0,
    createdAt: new Date().toISOString(),
  };
  const created = db.addWatchlist(newRule);
  res.status(201).json(created);
});

// GET /api/threat-graph
apiRouter.get('/threat-graph', (req: Request, res: Response) => {
  const brand = db.getBrand();
  const findings = db.getFindings();

  const nodes: ThreatGraphNode[] = [];
  const links: ThreatGraphLink[] = [];

  // Root Brand Node
  nodes.push({
    id: 'node-brand',
    label: brand.name,
    type: 'brand',
    meta: { website: brand.officialWebsite, aliases: brand.aliases },
  });

  // Official Domains
  brand.officialDomains.forEach((dom, idx) => {
    const id = `node-dom-${idx}`;
    nodes.push({ id, label: dom, type: 'official_domain' });
    links.push({ source: 'node-brand', target: id, relationship: 'Authorized Domain' });
  });

  // Official Apps
  brand.officialApps.forEach((app) => {
    nodes.push({
      id: app.id,
      label: `${app.appName} (${app.platform === 'google_play' ? 'Android' : 'iOS'})`,
      type: 'official_app',
      meta: { packageId: app.packageId, publisher: app.publisher },
    });
    links.push({ source: 'node-brand', target: app.id, relationship: 'Verified App' });
  });

  // Official Social
  brand.officialSocialAccounts.forEach((soc) => {
    nodes.push({
      id: soc.id,
      label: `@${soc.handle} (${soc.platform})`,
      type: 'official_social',
      meta: { verified: soc.verified },
    });
    links.push({ source: 'node-brand', target: soc.id, relationship: 'Official Handle' });
  });

  // Threats / Fake Apps / Impersonators
  findings.slice(0, 8).forEach((f) => {
    const isApp = f.assetType === 'mobile_application';
    const fakeId = `node-threat-${f.id}`;

    nodes.push({
      id: fakeId,
      label: f.candidateName,
      type: isApp ? 'fake_app' : 'suspicious_social',
      riskScore: f.riskScore,
      riskLevel: f.riskLevel,
      meta: {
        identifier: f.identifier,
        status: f.status,
        publisher: f.publisherOrDeveloper,
        explanation: f.summaryExplanation,
      },
    });

    // Link threat to brand
    links.push({
      source: 'node-brand',
      target: fakeId,
      relationship: isApp ? 'App Impersonation' : 'Social Spoof',
      riskFlag: true,
    });

    // If app has publisher mismatch, add suspicious publisher node
    if (isApp && f.publisherOrDeveloper) {
      const pubNodeId = `node-pub-${f.id}`;
      nodes.push({
        id: pubNodeId,
        label: f.publisherOrDeveloper,
        type: 'suspicious_publisher',
        riskLevel: f.riskLevel,
      });
      links.push({
        source: fakeId,
        target: pubNodeId,
        relationship: 'Published By (Unauthorized)',
        riskFlag: true,
      });
    }

    // If domain mismatch
    const domainSignal = f.signals.find((s) => s.type === 'domain_mismatch');
    if (domainSignal && domainSignal.highlightDetails?.candidateValue) {
      const simDomId = `node-simdom-${f.id}`;
      nodes.push({
        id: simDomId,
        label: domainSignal.highlightDetails.candidateValue,
        type: 'similar_domain',
        riskLevel: f.riskLevel,
      });
      links.push({
        source: fakeId,
        target: simDomId,
        relationship: 'Redirects To',
        riskFlag: true,
      });
    }
  });

  res.json({ nodes, links });
});

// GET /api/reports/export
apiRouter.get('/reports/export', (req: Request, res: Response) => {
  const { format } = req.query;
  const brand = db.getBrand();
  const findings = db.getFindings();

  if (format === 'csv') {
    const headers = [
      'ID',
      'Asset Type',
      'Platform',
      'Candidate Name',
      'Identifier',
      'Publisher/Developer',
      'Risk Score',
      'Risk Level',
      'Status',
      'First Seen',
      'Last Seen',
      'Recommended Action',
    ];
    const rows = findings.map((f) => [
      f.id,
      f.assetType,
      f.platform,
      `"${f.candidateName.replace(/"/g, '""')}"`,
      `"${f.identifier}"`,
      `"${(f.publisherOrDeveloper || '').replace(/"/g, '""')}"`,
      f.riskScore,
      f.riskLevel,
      f.status,
      f.firstSeen,
      f.lastSeen,
      `"${f.recommendedAction.replace(/"/g, '""')}"`,
    ]);

    const csvContent = [headers.join(','), ...rows.map((r) => r.join(','))].join('\n');
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', `attachment; filename="sentinelshield_threat_report_${Date.now()}.csv"`);
    res.send(csvContent);
    return;
  }

  // Default JSON report
  res.json({
    reportMetadata: {
      title: 'SentinelShield Executive Threat Assessment',
      organization: brand.name,
      generatedAt: new Date().toISOString(),
      reportVersion: '2.1',
      classification: 'CONFIDENTIAL // SOC RESTRICTED',
    },
    summaryMetrics: {
      totalMonitoredAssets: brand.officialApps.length + brand.officialSocialAccounts.length,
      activeThreatsCount: findings.filter((f) => f.status !== 'resolved' && f.status !== 'dismissed').length,
      criticalThreatsCount: findings.filter((f) => f.riskLevel === 'critical').length,
      highRiskThreatsCount: findings.filter((f) => f.riskLevel === 'high').length,
    },
    brandProfile: brand,
    findings,
  });
});

// GET /api/system/health
apiRouter.get('/system/health', (req: Request, res: Response) => {
  res.json(db.getSystemHealth());
});
