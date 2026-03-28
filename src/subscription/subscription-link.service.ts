import { Injectable } from '@nestjs/common';
import * as crypto from 'crypto';

const HAPP_CRYPTO_TIMEOUT_MS = 8000;

@Injectable()
export class SubscriptionLinkService {
  private readonly secret =
    process.env.SUBSCRIPTION_LINK_SECRET?.trim() ||
    process.env.LK_JWT_SECRET?.trim() ||
    process.env.JWT_SECRET?.trim() ||
    '';

  private readonly publicSiteUrl = (
    process.env.PUBLIC_SITE_URL ||
    process.env.SITE_URL ||
    ''
  ).replace(/\/$/, '');

  private readonly vpnConnectBase = (
    process.env.VPN_CONNECT_BASE_URL || 'https://connect.amnesiavps.ru'
  ).replace(/\/$/, '');

  private readonly happCryptoApi =
    process.env.HAPP_CRYPTO_API?.trim() || 'https://crypto.happ.su/api-v2.php';

  createSubscriptionToken(realUrl: string): string | null {
    if (!this.secret || !realUrl || realUrl === 'Ссылка недоступна') {
      return null;
    }
    const hmac = crypto
      .createHmac('sha256', this.secret)
      .update(realUrl, 'utf8')
      .digest('base64url');
    const payload = Buffer.from(realUrl, 'utf8').toString('base64url');
    return `${payload}.${hmac}`;
  }

  verifyTokenAndGetUrl(token: string | undefined): string | null {
    if (!token || typeof token !== 'string' || !this.secret) {
      return null;
    }
    const dot = token.indexOf('.');
    if (dot === -1) {
      return null;
    }
    const payloadB64 = token.slice(0, dot);
    const sig = token.slice(dot + 1);
    let realUrl: string;
    try {
      realUrl = Buffer.from(payloadB64, 'base64url').toString('utf8');
    } catch {
      return null;
    }
    const expected = crypto
      .createHmac('sha256', this.secret)
      .update(realUrl, 'utf8')
      .digest('base64url');
    if (sig !== expected) {
      return null;
    }
    return realUrl;
  }

  private async getHappEncryptedUrl(
    subscriptionUrl: string,
  ): Promise<string | null> {
    const trimmed = subscriptionUrl.trim();
    if (!trimmed.startsWith('http://') && !trimmed.startsWith('https://')) {
      return null;
    }
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), HAPP_CRYPTO_TIMEOUT_MS);
    try {
      const res = await fetch(this.happCryptoApi, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: trimmed }),
        signal: controller.signal,
      });
      clearTimeout(timeoutId);
      if (!res.ok) {
        return null;
      }
      const text = await res.text();
      const textTrimmed = text.trim();
      if (textTrimmed.startsWith('happ://')) {
        return textTrimmed;
      }
      try {
        const json = JSON.parse(text) as Record<string, unknown>;
        const link =
          (typeof json.encrypted_link === 'string' && json.encrypted_link) ||
          (typeof json.url === 'string' && json.url) ||
          (typeof json.link === 'string' && json.link) ||
          (typeof json.encrypted === 'string' && json.encrypted) ||
          null;
        return link;
      } catch {
        return null;
      }
    } catch {
      clearTimeout(timeoutId);
      return null;
    }
  }

  /**
   * Добавляет защищённую ссылку (как у бота: proxy + HMAC), прямую, Happ-шифр и ссылку на страницу connect.
   */
  async enrichServiceProfile(
    profile: Record<string, unknown>,
  ): Promise<Record<string, unknown>> {
    const raw = profile.subscription_url;
    if (typeof raw !== 'string' || !raw.trim()) {
      return {
        ...profile,
        subscription_url_direct: null,
        happ_encrypted_link: null,
        happ_open_url: null,
      };
    }
    const direct = raw.trim();
    const t = this.createSubscriptionToken(direct);
    const proxyUrl =
      t && this.publicSiteUrl
        ? `${this.publicSiteUrl}/api/subscription/proxy?t=${encodeURIComponent(t)}`
        : direct;

    const encrypted = await this.getHappEncryptedUrl(direct);
    const linkForConnect = encrypted || direct;
    const happOpenUrl = `${this.vpnConnectBase}/?link=${encodeURIComponent(linkForConnect)}`;

    return {
      ...profile,
      subscription_url_direct: direct,
      subscription_url: proxyUrl,
      happ_encrypted_link: encrypted,
      happ_open_url: happOpenUrl,
    };
  }
}
