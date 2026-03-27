import { Injectable, ServiceUnavailableException } from '@nestjs/common';
import { createHash } from 'crypto';

interface NormalizedNode {
  id: string;
  countryCode: string;
  countryName: string;
  name: string;
  online: boolean;
  loadPercent: number;
  usersOnline: number;
  activeUsers: number;
}

interface NodeSnapshot {
  uuid: string;
  countryCode: string;
  isConnected: boolean;
  usersOnline: number;
  trafficUsedBytes: number;
  pingMs: number;
}

interface InfraStats {
  onlineUsers: number;
  activeUsers: number;
  totalTrafficBytes: number;
  totalTrafficLabel: string;
  locations: number;
}

@Injectable()
export class RemnawaveService {
  private static readonly INFRA_CACHE_TTL_MS = 10 * 60 * 1000;
  private readonly baseUrl = (process.env.RW_API_BASE_URL ?? '').replace(/\/$/, '');
  private readonly token = process.env.RW_API_TOKEN ?? '';
  private readonly publicIdSalt = process.env.INFRA_PUBLIC_ID_SALT ?? 'infra-public';
  private readonly countryNames: Record<string, string> = {
    NL: 'Нидерланды',
    RU: 'Россия',
    DE: 'Германия',
    US: 'США',
  };
  private infraCache: { expiresAt: number; payload: unknown } | null = null;
  private inFlightRefresh: Promise<unknown> | null = null;

  private makeUrl(path: string): string {
    const cleanPath = path.startsWith('/') ? path : `/${path}`;
    if (this.baseUrl.endsWith('/api') && cleanPath.startsWith('/api/')) {
      return `${this.baseUrl}${cleanPath.slice(4)}`;
    }
    return `${this.baseUrl}${cleanPath}`;
  }

  private toPublicId(rawId: string): string {
    return createHash('sha256')
      .update(`${this.publicIdSalt}:${rawId}`)
      .digest('hex')
      .slice(0, 16);
  }

  private async remnawaveGet(path: string) {
    if (!this.baseUrl || !this.token) {
      throw new ServiceUnavailableException(
        'Remnawave не настроен. Укажите RW_API_BASE_URL и RW_API_TOKEN в .env',
      );
    }

    const response = await fetch(this.makeUrl(path), {
      headers: {
        Authorization: `Bearer ${this.token}`,
        Accept: 'application/json',
      },
    });

    const payload = await response.json().catch(() => ({}));

    if (!response.ok) {
      const msg =
        typeof payload?.message === 'string'
          ? payload.message
          : 'Ошибка запроса к Remnawave API';
      throw new ServiceUnavailableException(msg);
    }

    return payload;
  }

  async getRawNodes(): Promise<unknown> {
    return this.remnawaveGet('/api/nodes');
  }

  async getRawHosts(): Promise<unknown> {
    return this.remnawaveGet('/api/hosts');
  }

  async getRawUsers(size = 1000, start = 0): Promise<unknown> {
    return this.remnawaveGet(`/api/users?size=${size}&start=${start}`);
  }

  private getDataArray(payload: unknown): Record<string, unknown>[] {
    if (Array.isArray(payload)) return payload as Record<string, unknown>[];

    if (payload && typeof payload === 'object') {
      const p = payload as Record<string, unknown>;
      if (Array.isArray(p.response)) return p.response as Record<string, unknown>[];
      if (Array.isArray(p.data)) return p.data as Record<string, unknown>[];
      if (p.data && typeof p.data === 'object') {
        const d = p.data as Record<string, unknown>;
        if (Array.isArray(d.nodes)) return d.nodes as Record<string, unknown>[];
      }
      if (Array.isArray(p.nodes)) return p.nodes as Record<string, unknown>[];
    }

    return [];
  }

  private extractUsersArray(payload: unknown): Record<string, unknown>[] {
    if (!payload || typeof payload !== 'object') return [];
    const p = payload as Record<string, unknown>;
    if (Array.isArray(p.response)) return p.response as Record<string, unknown>[];
    if (p.response && typeof p.response === 'object') {
      const r = p.response as Record<string, unknown>;
      if (Array.isArray(r.users)) return r.users as Record<string, unknown>[];
    }
    if (Array.isArray(p.users)) return p.users as Record<string, unknown>[];
    return [];
  }

  private async getActiveUsersCountPaginated(pageSize = 1000): Promise<number | null> {
    let start = 0;
    let activeCount = 0;

    // Hard limit to avoid infinite loops on malformed pagination.
    for (let page = 0; page < 200; page += 1) {
      const raw = await this.getRawUsers(pageSize, start);
      const users = this.extractUsersArray(raw);
      if (users.length === 0) break;

      for (const user of users) {
        const status = this.readString(user, 'status').toUpperCase();
        if (status === 'ACTIVE') activeCount += 1;
      }

      if (users.length < pageSize) break;
      start += pageSize;
    }

    return activeCount;
  }

  private readString(node: Record<string, unknown>, ...keys: string[]) {
    for (const key of keys) {
      const v = node[key];
      if (typeof v === 'string' && v.trim()) return v.trim();
    }
    return '';
  }

  private readNumber(node: Record<string, unknown>, ...keys: string[]) {
    for (const key of keys) {
      const v = node[key];
      if (typeof v === 'number' && Number.isFinite(v)) return v;
      if (typeof v === 'string') {
        const parsed = Number(v);
        if (Number.isFinite(parsed)) return parsed;
      }
    }
    return 0;
  }

  private readBoolean(node: Record<string, unknown>, ...keys: string[]) {
    for (const key of keys) {
      const v = node[key];
      if (typeof v === 'boolean') return v;
      if (typeof v === 'number') return v > 0;
      if (typeof v === 'string') {
        const value = v.toLowerCase();
        if (value === 'online' || value === 'active' || value === 'up' || value === 'true') {
          return true;
        }
        if (value === 'offline' || value === 'down' || value === 'false') {
          return false;
        }
      }
    }
    return false;
  }

  private emojiFlag(code: string): string {
    if (!/^[A-Z]{2}$/.test(code)) return '🌐';
    const chars = code
      .split('')
      .map((c) => String.fromCodePoint(127397 + c.charCodeAt(0)));
    return chars.join('');
  }

  private resolveCountryName(code: string): string {
    if (!code) return 'Неизвестная страна';
    if (this.countryNames[code]) return this.countryNames[code];

    try {
      const intl = new Intl.DisplayNames(['ru'], { type: 'region' });
      return intl.of(code) ?? code;
    } catch {
      return code;
    }
  }

  private normalizeNodeSnapshot(node: Record<string, unknown>): NodeSnapshot {
    return {
      uuid: this.readString(node, 'uuid', 'id'),
      countryCode: this.readString(node, 'countryCode', 'country').slice(0, 2).toUpperCase() || 'UN',
      isConnected: this.readBoolean(node, 'isConnected'),
      usersOnline: Math.max(0, Math.round(this.readNumber(node, 'usersOnline', 'onlineUsers'))),
      trafficUsedBytes: Math.max(0, this.readNumber(node, 'trafficUsedBytes', 'trafficBytes')),
      pingMs: Math.max(1, Math.round(this.readNumber(node, 'pingMs', 'ping', 'latencyMs', 'latency') || 45)),
    };
  }

  private normalizeHost(
    host: Record<string, unknown>,
    index: number,
    nodeMap: Map<string, NodeSnapshot>,
  ): NormalizedNode {
    const hostNodeRefs = Array.isArray(host.nodes)
      ? host.nodes.filter((v): v is string => typeof v === 'string')
      : [];
    const linked = hostNodeRefs
      .map((uuid) => nodeMap.get(uuid))
      .filter((n): n is NodeSnapshot => Boolean(n));

    const connectedByNode = linked.some((n) => n.isConnected);
    const online = !this.readBoolean(host, 'isDisabled') && connectedByNode;
    const usersOnline = linked.reduce((sum, n) => sum + n.usersOnline, 0);
    const firstNode = linked[0];
    const countryCode =
      (firstNode?.countryCode || this.readString(host, 'countryCode', 'country').slice(0, 2) || 'UN').toUpperCase();
    const rawId = this.readString(host, 'uuid', 'id') || `host-${index + 1}`;
    const displayName = this.readString(host, 'remark', 'name', 'tag') || `Host ${index + 1}`;

    return {
      id: this.toPublicId(rawId),
      countryCode,
      countryName: this.resolveCountryName(countryCode),
      name: displayName,
      online,
      // По ТЗ: usersOnline напрямую означает % нагрузки.
      loadPercent: Math.max(0, Math.min(100, usersOnline)),
      usersOnline,
      activeUsers: usersOnline,
    };
  }

  private formatTraffic(bytes: number): string {
    if (!Number.isFinite(bytes) || bytes <= 0) return '0 B';
    const units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
    let size = bytes;
    let unit = 0;
    while (size >= 1024 && unit < units.length - 1) {
      size /= 1024;
      unit += 1;
    }
    return `${size.toFixed(size >= 100 || unit === 0 ? 0 : 1)} ${units[unit]}`;
  }

  private async buildInfrastructurePayload(): Promise<unknown> {
    const [hostsRaw, nodesRaw, paginatedActiveUsers] = await Promise.all([
      this.getRawHosts(),
      this.getRawNodes(),
      this.getActiveUsersCountPaginated().catch(() => null),
    ]);
    const hostsRows = this.getDataArray(hostsRaw);
    const nodesRows = this.getDataArray(nodesRaw);

    const nodeMap = new Map<string, NodeSnapshot>();
    for (const row of nodesRows) {
      const snap = this.normalizeNodeSnapshot(row);
      if (snap.uuid) nodeMap.set(snap.uuid, snap);
    }

    const nodes = hostsRows.map((host, i) => this.normalizeHost(host, i, nodeMap));

    const onlineUsers = nodes.reduce((sum, n) => sum + n.usersOnline, 0);
    let activeUsers = nodes.reduce((sum, n) => sum + (n.activeUsers || n.usersOnline), 0);
    if (typeof paginatedActiveUsers === 'number') {
      activeUsers = paginatedActiveUsers;
    }
    const totalTrafficBytes = nodesRows.reduce(
      (sum, row) => sum + Math.max(0, this.readNumber(row, 'trafficUsedBytes')),
      0,
    );

    const stats: InfraStats = {
      onlineUsers,
      activeUsers,
      totalTrafficBytes,
      totalTrafficLabel: this.formatTraffic(totalTrafficBytes),
      // По запросу UI: количество именно серверов (nodes), а не hosts.
      locations: nodesRows.length,
    };

    const safeNodes = nodes.map((node) => ({
      id: node.id,
      name: node.name,
      countryCode: node.countryCode,
      countryName: node.countryName,
      online: node.online,
      loadPercent: node.loadPercent,
    }));

    return {
      nodes: safeNodes,
      stats,
      updatedAt: new Date().toISOString(),
    };
  }

  async getInfrastructure(): Promise<unknown> {
    const now = Date.now();
    if (this.infraCache && this.infraCache.expiresAt > now) {
      return this.infraCache.payload;
    }

    if (!this.inFlightRefresh) {
      this.inFlightRefresh = this.buildInfrastructurePayload()
        .then((payload) => {
          this.infraCache = {
            payload,
            expiresAt: Date.now() + RemnawaveService.INFRA_CACHE_TTL_MS,
          };
          return payload;
        })
        .finally(() => {
          this.inFlightRefresh = null;
        });
    }

    return this.inFlightRefresh;
  }
}
