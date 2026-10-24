import { createHash, randomBytes, scryptSync, timingSafeEqual } from 'node:crypto';
import type { NextFunction, Request, Response } from 'express';
import type { User } from '../src/types/index.js';
import { SessionModel, UserModel } from './models.js';

export const DEMO_CREDENTIALS = [
  {
    email: 'analyst1@sentinelshield.demo',
    passwordSalt: 'sentinel-analyst1-v1',
    passwordHash: 'd459e8d6b748bb8ff3ec6b69b581312c3d6ff3f24d0210534a4c9a8ef144a280721ab8e1151f727fc85d2da1595b7a5e07723e5854e1f5d9008fb005c60d9b53',
    userId: 'usr-analyst-1',
  },
  {
    email: 'analyst2@sentinelshield.demo',
    passwordSalt: 'sentinel-analyst2-v1',
    passwordHash: '70c013251151ac2ef0666590024b33e63eddd1d991d5ec0f3288e4da9a339f31669f9a94361fd16e6f7cadb66f1957d6a98f4714588ab5346e251dd37db30ed6',
    userId: 'usr-analyst-2',
  },
  {
    email: 'admin@sentinelshield.demo',
    passwordSalt: 'sentinel-admin-v1',
    passwordHash: '00a8dea301ae26d9a9d977f71dee0e0faddfe89d709bd98f9a3e66034b590c704740aec349c91838059f089d86bd34a60fd6ee479a9055a910ed0b6599086b83',
    userId: 'usr-admin-1',
  },
] as const;

function hashToken(token: string): string {
  return createHash('sha256').update(token).digest('hex');
}

export async function createDemoSession(email: string, password: string, users: User[]) {
  const credentials = DEMO_CREDENTIALS.find((item) => item.email === email.trim().toLowerCase());
  if (!credentials) return null;
  const supplied = scryptSync(password, credentials.passwordSalt, 64);
  const expected = Buffer.from(credentials.passwordHash, 'hex');
  if (!timingSafeEqual(supplied, expected)) return null;
  const user = users.find((item) => item.id === credentials.userId);
  if (!user) throw new Error(`Configured demo user ${credentials.userId} is missing.`);
  const token = randomBytes(32).toString('base64url');
  const expiresAt = new Date(Date.now() + 8 * 60 * 60 * 1000);
  await SessionModel.create({ tokenHash: hashToken(token), userId: user.id, expiresAt });
  return { token, user, expiresAt: expiresAt.toISOString() };
}

export async function revokeSession(token: string) {
  await SessionModel.deleteOne({ tokenHash: hashToken(token) });
}

export async function currentUser(token: string | undefined): Promise<User | null> {
  if (!token) return null;
  const session = await SessionModel.findOne({
    tokenHash: hashToken(token),
    expiresAt: { $gt: new Date() },
  }).lean().exec();
  if (!session) return null;
  const user = await UserModel.findOne({ id: session.userId }).lean().exec();
  if (!user) throw new Error(`Session references missing demo user ${session.userId}.`);
  const { _id: _mongoId, __v: _version, passwordHash: _passwordHash, passwordSalt: _passwordSalt, ...publicUser } = user;
  return publicUser as User;
}

export interface AuthenticatedRequest extends Request {
  user?: User;
  sessionToken?: string;
}

export async function requireSession(req: Request, res: Response, next: NextFunction) {
  const token = req.header('authorization')?.replace(/^Bearer\s+/i, '');
  try {
    const user = await currentUser(token);
    if (!user) {
      res.status(401).json({ error: 'A valid demo login session is required.' });
      return;
    }
    const authenticatedRequest = req as AuthenticatedRequest;
    authenticatedRequest.user = user;
    authenticatedRequest.sessionToken = token;
    next();
  } catch (error) {
    next(error);
  }
}
