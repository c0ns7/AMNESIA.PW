import { existsSync } from 'fs';
import { join } from 'path';

/** Каталог public: рядом с dist или из cwd (systemd / pm2). */
export function resolvePublicRoot(scriptDir: string): string {
  const fromDist = join(scriptDir, '..', 'public');
  const fromCwd = join(process.cwd(), 'public');
  if (existsSync(join(fromDist, 'index.html'))) return fromDist;
  if (existsSync(join(fromCwd, 'index.html'))) return fromCwd;
  return fromDist;
}
