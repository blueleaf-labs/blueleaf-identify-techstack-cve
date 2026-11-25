import { ApplicationError } from "../../domain/errors.js";
import type {
  Evidence,
  EvidenceCollection,
  EvidenceSource,
  EvidenceStrength,
  EvidenceType,
} from "../../domain/evidence.js";
import type { HttpResponse } from "../ports.js";

export const DEFAULT_EVIDENCE_BODY_LIMIT = 512 * 1024;
export const DEFAULT_EVIDENCE_ITEM_LIMIT = 512;
export const MAX_EVIDENCE_BODY_LIMIT = 2 * 1024 * 1024;
export const MAX_EVIDENCE_ITEM_LIMIT = 4096;

export interface EvidenceEngineOptions {
  readonly maxBodyBytes?: number;
  readonly maxEvidenceItems?: number;
}

export interface EvidenceCollector {
  collect(probe: HttpResponse): EvidenceCollection;
}

const MAX_TEXT_VALUE = 512;
const MAX_URL_VALUE = 2048;
const MAX_TAG_LENGTH = 8192;
const MAX_HTML_TAGS = 20_000;
const MAX_VERSION_MATCHES = 32;
const VERSION_PATTERN =
  /(?<![A-Za-z0-9])v?(\d+(?:\.\d+){1,3}(?:-[0-9A-Za-z][0-9A-Za-z.-]*)?(?:\+[0-9A-Za-z][0-9A-Za-z.-]*)?)(?![A-Za-z0-9]|\.\d)/g;
const SENSITIVE_HEADER_PATTERN =
  /authorization|authenticate|cookie|token|secret|api[-_]?key|password|session|csrf|nonce/i;
const SENSITIVE_COOKIE_PATTERN =
  /token|secret|api[-_]?key|password|session|auth|csrf|nonce/i;
const SENSITIVE_META_PATTERN =
  /csrf|xsrf|authorization|auth[-_.]?token|api[-_.]?key|access[-_.]?token|refresh(?:[-_.]?token)?|session(?:[-_.]?id)?|password|secret|nonce|cookie|verification|challenge/i;
const URL_HEADER_NAMES = new Set(["location", "content-location", "referer", "referrer"]);

function compareText(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function replaceUnsafeControls(value: string, preserveWhitespace: boolean): string {
  let result = "";
  for (const character of value) {
    const codePoint = character.codePointAt(0) ?? 0;
    const whitespaceControl =
      preserveWhitespace && [0x09, 0x0a, 0x0d].includes(codePoint);
    if (
      (codePoint <= 0x1f && !whitespaceControl) ||
      (codePoint >= 0x7f && codePoint <= 0x9f)
    ) {
      result += " ";
    } else {
      result += character;
    }
  }
  return result;
}

function boundedText(value: string, maximum: number): string {
  const normalized = value.normalize("NFKC");
  const safeNormalized = replaceUnsafeControls(normalized, true)
    .replace(/[\t\r\n ]+/g, " ")
    .trim();
  if (safeNormalized.length <= maximum) return safeNormalized;
  return `${safeNormalized.slice(0, Math.max(0, maximum - 1))}…`;
}

/** Canonical text normalization used for externally sourced evidence strings. */
export function normalizeEvidenceText(value: string): string {
  return boundedText(value, MAX_TEXT_VALUE);
}

function rawText(value: string, maximum = MAX_TEXT_VALUE): string {
  const sanitized = replaceUnsafeControls(value, false);
  if (sanitized.length <= maximum) return sanitized;
  return `${sanitized.slice(0, Math.max(0, maximum - 1))}…`;
}

/** Resolve a passive URL reference and remove credentials, queries, and fragments. */
export function normalizeEvidenceUrl(value: string, baseUrl: string): string | undefined {
  try {
    const url = new URL(decodeHtmlEntities(value.trim()), baseUrl);
    if ((url.protocol !== "http:" && url.protocol !== "https:") || !url.hostname) {
      return undefined;
    }
    if (!url.hostname.startsWith("[") && url.hostname.endsWith(".")) {
      url.hostname = url.hostname.slice(0, -1);
    }
    url.username = "";
    url.password = "";
    url.search = "";
    url.hash = "";
    return boundedText(url.href, MAX_URL_VALUE);
  } catch {
    return undefined;
  }
}

/** Extract the first generic version-like token; this does not establish ownership or truth. */
export function extractVersionHint(value: string): string | undefined {
  VERSION_PATTERN.lastIndex = 0;
  let checked = 0;
  for (const match of value.matchAll(VERSION_PATTERN)) {
    checked += 1;
    if (checked > MAX_VERSION_MATCHES) return undefined;
    const candidate = match[1];
    if (candidate === undefined || isIPv4Literal(candidate)) continue;
    return candidate.toLowerCase();
  }
  return undefined;
}

function isIPv4Literal(value: string): boolean {
  const parts = value.split(".");
  return (
    parts.length === 4 &&
    parts.every((part) => /^\d{1,3}$/.test(part) && Number(part) <= 255)
  );
}

function decodeHtmlEntities(value: string): string {
  return value.replace(
    /&(#(?:x[\da-f]+|\d+)|amp|lt|gt|quot|apos|nbsp);/gi,
    (entity, token: string) => {
      if (token[0] === "#") {
        const hexadecimal = token[1]?.toLowerCase() === "x";
        const digits = token.slice(hexadecimal ? 2 : 1);
        const codePoint = Number.parseInt(digits, hexadecimal ? 16 : 10);
        if (Number.isInteger(codePoint) && codePoint >= 0 && codePoint <= 0x10ffff) {
          return String.fromCodePoint(codePoint);
        }
        return entity;
      }
      const named: Readonly<Record<string, string>> = {
        amp: "&",
        lt: "<",
        gt: ">",
        quot: '"',
        apos: "'",
        nbsp: " ",
      };
      return named[token.toLowerCase()] ?? entity;
    },
  );
}

function safeUrlValue(value: string, baseUrl: string): string | undefined {
  return normalizeEvidenceUrl(value, baseUrl);
}

interface HtmlAttributeSet {
  readonly tagName: string;
  readonly closing: boolean;
  readonly attributes: Readonly<Record<string, string>>;
  readonly rawAttributes: Readonly<Record<string, string>>;
}

function findTagEnd(html: string, start: number): number {
  let quote = "";
  const maximum = Math.min(html.length, start + MAX_TAG_LENGTH);
  for (let index = start; index < maximum; index += 1) {
    const character = html[index];
    if (
      (character === '"' || character === "'") &&
      (quote === "" || quote === character)
    ) {
      quote = quote === "" ? character : "";
    } else if (character === ">" && quote === "") {
      return index;
    }
  }
  return -1;
}

function parseHtmlTag(
  html: string,
  start: number,
  end: number,
): HtmlAttributeSet | undefined {
  const contents = html.slice(start + 1, end);
  let index = 0;
  while (/\s/.test(contents[index] ?? "")) index += 1;
  let closing = false;
  if (contents[index] === "/") {
    closing = true;
    index += 1;
    while (/\s/.test(contents[index] ?? "")) index += 1;
  }
  const nameStart = index;
  while (/[A-Za-z0-9:-]/.test(contents[index] ?? "")) index += 1;
  if (index === nameStart) return undefined;
  const tagName = contents.slice(nameStart, index).toLowerCase();
  const attributes: Record<string, string> = Object.create(null) as Record<
    string,
    string
  >;
  const rawAttributes: Record<string, string> = Object.create(null) as Record<
    string,
    string
  >;

  while (!closing && index < contents.length) {
    while (/\s|\//.test(contents[index] ?? "")) index += 1;
    if (index >= contents.length) break;
    const attributeStart = index;
    while (index < contents.length && !/[\s=/>]/.test(contents[index] ?? "")) index += 1;
    if (index === attributeStart) {
      index += 1;
      continue;
    }
    const attributeName = contents.slice(attributeStart, index).toLowerCase();
    while (/\s/.test(contents[index] ?? "")) index += 1;
    let attributeValue = "";
    if (contents[index] === "=") {
      index += 1;
      while (/\s/.test(contents[index] ?? "")) index += 1;
      const quote = contents[index];
      if (quote === '"' || quote === "'") {
        index += 1;
        const valueStart = index;
        while (index < contents.length && contents[index] !== quote) index += 1;
        attributeValue = contents.slice(valueStart, index);
        if (contents[index] === quote) index += 1;
      } else {
        const valueStart = index;
        while (index < contents.length && !/[\s>]/.test(contents[index] ?? ""))
          index += 1;
        attributeValue = contents.slice(valueStart, index);
      }
    }
    if (!(attributeName in attributes)) {
      attributes[attributeName] = decodeHtmlEntities(attributeValue);
      rawAttributes[attributeName] = attributeValue;
    }
  }

  return { tagName, closing, attributes, rawAttributes };
}

function cookieEvidenceParts(value: string): {
  readonly name: string;
  readonly normalizedValue: string;
  readonly rawValue: string;
} {
  const firstPart = value.split(";", 1)[0] ?? "";
  const equals = firstPart.indexOf("=");
  const rawName = equals >= 0 ? firstPart.slice(0, equals).trim() : "";
  const name = normalizeEvidenceText(rawName).toLowerCase();
  const validName = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/.test(rawName);
  const cookieName =
    !validName || SENSITIVE_COOKIE_PATTERN.test(name) ? "<redacted-name>" : name;
  return {
    name: cookieName,
    normalizedValue: `${cookieName}=<redacted>`,
    rawValue: `${cookieName}=<redacted>`,
  };
}

export class EvidenceEngine implements EvidenceCollector {
  private readonly maxBodyBytes: number;
  private readonly maxEvidenceItems: number;

  public constructor(options: EvidenceEngineOptions = {}) {
    this.maxBodyBytes = options.maxBodyBytes ?? DEFAULT_EVIDENCE_BODY_LIMIT;
    this.maxEvidenceItems = options.maxEvidenceItems ?? DEFAULT_EVIDENCE_ITEM_LIMIT;
    if (
      !Number.isSafeInteger(this.maxBodyBytes) ||
      this.maxBodyBytes < 0 ||
      this.maxBodyBytes > MAX_EVIDENCE_BODY_LIMIT
    ) {
      throw new ApplicationError(
        "INVALID_CONFIGURATION",
        `Evidence body limit must be an integer from 0 to ${MAX_EVIDENCE_BODY_LIMIT}.`,
      );
    }
    if (
      !Number.isSafeInteger(this.maxEvidenceItems) ||
      this.maxEvidenceItems < 1 ||
      this.maxEvidenceItems > MAX_EVIDENCE_ITEM_LIMIT
    ) {
      throw new ApplicationError(
        "INVALID_CONFIGURATION",
        `Evidence item limit must be an integer from 1 to ${MAX_EVIDENCE_ITEM_LIMIT}.`,
      );
    }
  }

  public collect(probe: HttpResponse): EvidenceCollection {
    const evidence: Evidence[] = [];
    let evidenceTruncated = false;
    const add = (
      type: EvidenceType,
      source: EvidenceSource,
      value: string,
      strength: EvidenceStrength,
      reason: string,
      options: {
        readonly rawValue?: string;
        readonly key?: string;
        readonly versionValue?: string;
      } = {},
    ): boolean => {
      if (evidence.length >= this.maxEvidenceItems) {
        evidenceTruncated = true;
        return false;
      }
      const normalizedValue = boundedText(
        value,
        type.endsWith("url") ? MAX_URL_VALUE : MAX_TEXT_VALUE,
      );
      const extractedVersionHint = extractVersionHint(
        options.versionValue ?? normalizedValue,
      );
      const versionHint =
        extractedVersionHint === undefined
          ? undefined
          : boundedText(extractedVersionHint, 128);
      const baseReason = boundedText(reason, 256);
      evidence.push({
        type,
        source,
        normalizedValue,
        ...(options.rawValue !== undefined
          ? { rawValue: rawText(options.rawValue) }
          : {}),
        ...(options.key !== undefined ? { key: boundedText(options.key, 128) } : {}),
        ...(versionHint !== undefined ? { versionHint } : {}),
        strength,
        reason:
          versionHint === undefined
            ? baseReason
            : boundedText(
                `${baseReason.slice(0, 120)} A version-like token was observed; it is unverified as a technology version.`,
                256,
              ),
      });
      return true;
    };

    add(
      "http-status",
      "probe.status",
      String(probe.status),
      "direct",
      "The HTTP response status was observed directly.",
    );

    const finalUrl = safeUrlValue(probe.finalUrl, probe.finalUrl);
    if (finalUrl !== undefined) {
      add(
        "final-url",
        "probe.final-url",
        finalUrl,
        "direct",
        "The normalized final response URL was observed directly.",
        { rawValue: finalUrl },
      );
    }

    const headerEntries = Object.entries(probe.headers).sort(([left], [right]) => {
      const normalizedOrder = compareText(left.toLowerCase(), right.toLowerCase());
      return normalizedOrder || compareText(left, right);
    });
    const normalizedHeaderNames = new Set<string>();
    for (const [rawName, rawValue] of headerEntries) {
      const key = normalizeEvidenceText(rawName).toLowerCase();
      normalizedHeaderNames.add(key);
      if (key === "set-cookie") continue;
      const sensitive = SENSITIVE_HEADER_PATTERN.test(key);
      const safeHeaderUrl =
        !sensitive && URL_HEADER_NAMES.has(key)
          ? normalizeEvidenceUrl(rawValue, probe.finalUrl)
          : undefined;
      const normalizedValue = sensitive
        ? "<redacted>"
        : URL_HEADER_NAMES.has(key)
          ? (safeHeaderUrl ?? "<non-http-url>")
          : normalizeEvidenceText(rawValue);
      add(
        "header",
        "response.headers",
        normalizedValue,
        "direct",
        sensitive
          ? `Response header ${key} was observed; its value was redacted.`
          : `Response header ${key} was observed directly.`,
        {
          ...(sensitive
            ? {}
            : { rawValue: URL_HEADER_NAMES.has(key) ? normalizedValue : rawValue }),
          key,
        },
      );
    }

    const legacyCookieHeaders = headerEntries
      .filter(([name]) => name.toLowerCase() === "set-cookie")
      .map(([, value]) => value);
    const cookies =
      probe.cookies && probe.cookies.length > 0 ? probe.cookies : legacyCookieHeaders;
    for (const cookie of cookies) {
      const cookieParts = cookieEvidenceParts(cookie);
      add(
        "cookie",
        "response.cookies",
        cookieParts.normalizedValue,
        "direct",
        `Response cookie ${cookieParts.name} was observed; its value and attributes were redacted.`,
        { rawValue: cookieParts.rawValue, key: cookieParts.name },
      );
    }

    if (probe.contentType !== undefined && !normalizedHeaderNames.has("content-type")) {
      const normalized = normalizeEvidenceText(probe.contentType).toLowerCase();
      add(
        "content-type",
        "probe.content-type",
        normalized,
        "direct",
        "The normalized response content type was observed directly.",
        { rawValue: probe.contentType },
      );
    }
    if (
      probe.contentLength !== undefined &&
      !normalizedHeaderNames.has("content-length")
    ) {
      add(
        "content-length",
        "probe.content-length",
        String(probe.contentLength),
        "direct",
        "The declared response content length was observed directly.",
      );
    }

    for (const [index, hop] of (probe.redirectChain ?? []).entries()) {
      const from = safeUrlValue(hop.from, probe.finalUrl);
      const to = safeUrlValue(hop.to, probe.finalUrl);
      if (from === undefined || to === undefined) continue;
      const value = `${hop.status} ${from} -> ${to}`;
      add(
        "redirect",
        "probe.redirect-chain",
        value,
        "direct",
        `Redirect hop ${index + 1} and its status were observed by the probe.`,
        { rawValue: value },
      );
    }

    const tls = probe.tls;
    if (tls !== undefined) {
      add(
        "tls",
        "probe.tls",
        `authorized=${tls.authorized}`,
        "direct",
        "TLS authorization state was reported by the probe.",
        { key: "authorized" },
      );
      for (const [key, value] of [
        ["protocol", tls.protocol],
        ["cipher", tls.cipher],
        ["subjectAltName", tls.peerCertificate?.subjectAltName],
        ["fingerprint256", tls.peerCertificate?.fingerprint256],
        ["validFrom", tls.peerCertificate?.validFrom],
        ["validTo", tls.peerCertificate?.validTo],
      ] as const) {
        if (value === undefined) continue;
        add(
          "tls",
          "probe.tls",
          normalizeEvidenceText(value),
          "direct",
          `TLS ${key} metadata was reported by the probe.`,
          { key },
        );
      }
    }

    const addresses = [...new Set(probe.resolvedAddresses ?? [])].sort(compareText);
    for (const address of addresses) {
      add(
        "network",
        "probe.network",
        address.toLowerCase(),
        "direct",
        "A target address checked by the probe was observed.",
        { key: "resolved-address" },
      );
    }
    if (probe.remoteAddress !== undefined) {
      add(
        "network",
        "probe.network",
        probe.remoteAddress.toLowerCase(),
        "direct",
        "The connected peer address was reported by the probe.",
        { key: "remote-address" },
      );
    }
    if (probe.timing !== undefined) {
      add(
        "timing",
        "probe.timing",
        `duration-ms=${probe.timing.durationMs.toFixed(3)}`,
        "direct",
        "Elapsed request timing was reported by the probe.",
        { key: "duration-ms" },
      );
      for (const [key, value] of [
        ["requestStartedAt", probe.timing.requestStartedAt],
        ["responseReceivedAt", probe.timing.responseReceivedAt],
        ["completedAt", probe.timing.completedAt],
      ] as const) {
        add(
          "timing",
          "probe.timing",
          value,
          "direct",
          `Probe ${key} timestamp was reported.`,
          { key },
        );
      }
    }

    const bodyBytesReceived = probe.body.byteLength;
    const bodyBytesExamined = Math.min(bodyBytesReceived, this.maxBodyBytes);
    const bodyTruncated = bodyBytesExamined < bodyBytesReceived;
    const bodyText = new TextDecoder("utf-8").decode(
      probe.body.subarray(0, bodyBytesExamined),
    );
    const signature = this.collectBodyEvidence(
      bodyText,
      probe.finalUrl,
      probe.contentType ??
        headerEntries.find(([name]) => name.toLowerCase() === "content-type")?.[1],
      add,
      () => {
        evidenceTruncated = true;
      },
    );
    evidenceTruncated ||= signature.truncated;

    return {
      schemaVersion: "1.0",
      evidence,
      processing: {
        bodyBytesReceived,
        bodyBytesExamined,
        bodyTruncated,
        evidenceTruncated,
      },
    };
  }

  private collectBodyEvidence(
    bodyText: string,
    finalUrl: string,
    contentType: string | undefined,
    add: (
      type: EvidenceType,
      source: EvidenceSource,
      value: string,
      strength: EvidenceStrength,
      reason: string,
      options?: {
        readonly rawValue?: string;
        readonly key?: string;
        readonly versionValue?: string;
      },
    ) => boolean,
    markTruncated: () => void,
  ): { readonly truncated: boolean } {
    if (bodyText.length === 0) return { truncated: false };
    const trimmed = bodyText.replace(/^\uFEFF/, "").trimStart();
    const markers: readonly {
      readonly pattern: RegExp;
      readonly value: string;
      readonly reason: string;
    }[] = [
      {
        pattern: /^<!doctype\s+html\b/i,
        value: "html-doctype",
        reason: "The response body begins with an HTML doctype marker.",
      },
      {
        pattern: /^<html\b/i,
        value: "html-root",
        reason: "The response body begins with an HTML root element.",
      },
      {
        pattern: /^<\?xml\b/i,
        value: "xml-declaration",
        reason: "The response body begins with an XML declaration.",
      },
      {
        pattern: /^\{/s,
        value: "json-object-like",
        reason: "The response body begins with an object-shaped JSON marker.",
      },
      {
        pattern: /^\[/s,
        value: "json-array-like",
        reason: "The response body begins with an array-shaped JSON marker.",
      },
    ];
    for (const marker of markers) {
      if (!marker.pattern.test(trimmed)) continue;
      if (
        !add(
          "content-marker",
          "response.body.signature",
          marker.value,
          "derived",
          marker.reason,
          { rawValue: marker.pattern.exec(trimmed)?.[0] ?? marker.value },
        )
      ) {
        markTruncated();
        return { truncated: true };
      }
      break;
    }

    const htmlLike =
      /^\s*(?:text\/html|application\/xhtml\+xml)\b/i.test(contentType ?? "") ||
      /^(?:<!--[\s\S]*?-->\s*)*(?:<!doctype\s+html\b|<[a-z][a-z0-9:-]*(?=\s|\/?\s*>))/i.test(
        trimmed,
      );
    if (!htmlLike) return { truncated: false };
    return this.parseHtml(bodyText, finalUrl, add, markTruncated);
  }

  private parseHtml(
    html: string,
    finalUrl: string,
    add: (
      type: EvidenceType,
      source: EvidenceSource,
      value: string,
      strength: EvidenceStrength,
      reason: string,
      options?: {
        readonly rawValue?: string;
        readonly key?: string;
        readonly versionValue?: string;
      },
    ) => boolean,
    markTruncated: () => void,
  ): { readonly truncated: boolean } {
    let index = 0;
    let tagCount = 0;
    while (index < html.length && tagCount < MAX_HTML_TAGS) {
      const start = html.indexOf("<", index);
      if (start < 0) return { truncated: false };
      if (html.startsWith("<!--", start)) {
        const commentEnd = html.indexOf("-->", start + 4);
        if (commentEnd < 0) return { truncated: false };
        index = commentEnd + 3;
        continue;
      }

      const end = findTagEnd(html, start);
      if (end < 0) return { truncated: false };
      const tag = parseHtmlTag(html, start, end);
      index = end + 1;
      if (!tag) continue;
      tagCount += 1;
      if (tag.closing) continue;

      if (tag.tagName === "meta") {
        const metaName = normalizeEvidenceText(
          tag.attributes["name"] ??
            tag.attributes["property"] ??
            tag.attributes["itemprop"] ??
            tag.attributes["http-equiv"] ??
            "",
        ).toLowerCase();
        const content = tag.attributes["content"];
        if (!metaName || content === undefined) continue;
        const generator = metaName === "generator";
        const sensitive = SENSITIVE_META_PATTERN.test(metaName);
        if (
          !add(
            generator ? "html-generator" : "html-meta",
            generator ? "html.generator" : "html.meta",
            sensitive ? "<redacted>" : normalizeEvidenceText(content),
            "derived",
            sensitive
              ? `HTML meta content for ${metaName} was observed; its value was redacted.`
              : generator
                ? "A meta generator value was present; it is retained as a description, not a verdict."
                : `HTML meta content for ${metaName} was observed.`,
            {
              key: metaName,
              ...(sensitive ? {} : { rawValue: tag.rawAttributes["content"] ?? content }),
            },
          )
        ) {
          markTruncated();
          return { truncated: true };
        }
      } else if (tag.tagName === "script") {
        const url = tag.attributes["src"];
        if (url !== undefined) {
          const normalized = normalizeEvidenceUrl(url, finalUrl);
          if (
            normalized !== undefined &&
            !add(
              "script-url",
              "html.script.src",
              normalized,
              "derived",
              "An external script URL was referenced by the response HTML.",
              { rawValue: normalized, versionValue: normalized },
            )
          ) {
            markTruncated();
            return { truncated: true };
          }
        }
      } else if (tag.tagName === "link") {
        const href = tag.attributes["href"];
        if (href !== undefined) {
          const normalized = normalizeEvidenceUrl(href, finalUrl);
          const rel = normalizeEvidenceText(tag.attributes["rel"] ?? "")
            .toLowerCase()
            .split(" ");
          if (normalized !== undefined) {
            const stylesheet = rel.includes("stylesheet");
            if (
              !add(
                stylesheet ? "stylesheet-url" : "asset-url",
                stylesheet ? "html.link.stylesheet" : "html.asset.url",
                normalized,
                "derived",
                stylesheet
                  ? "A stylesheet URL was referenced by the response HTML."
                  : "A link relation referenced an external URL.",
                { key: rel.join(" "), rawValue: normalized, versionValue: normalized },
              )
            ) {
              markTruncated();
              return { truncated: true };
            }
          }
        }
      } else if (tag.tagName === "title") {
        const close = /<\/\s*title\s*>/gi;
        close.lastIndex = index;
        const closing = close.exec(html);
        const titleEnd = closing?.index ?? html.length;
        const title = normalizeEvidenceText(
          decodeHtmlEntities(html.slice(index, Math.min(titleEnd, index + 2048))),
        );
        if (
          title &&
          !add(
            "html-title",
            "html.title",
            title,
            "derived",
            "The HTML document title text was observed.",
            { rawValue: html.slice(index, Math.min(titleEnd, index + MAX_TEXT_VALUE)) },
          )
        ) {
          markTruncated();
          return { truncated: true };
        }
        index = closing ? close.lastIndex : html.length;
      } else {
        const attributes: readonly [string, string][] = [
          ["src", tag.attributes["src"] ?? ""],
          ["data-src", tag.attributes["data-src"] ?? ""],
          ["data-href", tag.attributes["data-href"] ?? ""],
          ["poster", tag.attributes["poster"] ?? ""],
          ["data", tag.attributes["data"] ?? ""],
          [
            "href",
            tag.tagName === "image"
              ? (tag.attributes["href"] ?? tag.attributes["xlink:href"] ?? "")
              : "",
          ],
        ];
        for (const [attribute, reference] of attributes) {
          if (!reference) continue;
          const normalized = normalizeEvidenceUrl(reference, finalUrl);
          if (normalized === undefined) continue;
          if (
            !add(
              "asset-url",
              "html.asset.url",
              normalized,
              "derived",
              `An HTML ${tag.tagName} ${attribute} attribute referenced a URL.`,
              {
                key: `${tag.tagName}.${attribute}`,
                rawValue: normalized,
                versionValue: normalized,
              },
            )
          ) {
            markTruncated();
            return { truncated: true };
          }
        }
        for (const srcset of [tag.attributes["srcset"], tag.attributes["imagesrcset"]]) {
          if (srcset === undefined) continue;
          for (const candidate of srcset.split(",")) {
            const reference = candidate.trim().split(/\s+/, 1)[0];
            if (!reference) continue;
            const normalized = normalizeEvidenceUrl(reference, finalUrl);
            if (normalized === undefined) continue;
            if (
              !add(
                "asset-url",
                "html.asset.url",
                normalized,
                "derived",
                `An HTML ${tag.tagName} srcset attribute referenced a URL.`,
                {
                  key: `${tag.tagName}.srcset`,
                  rawValue: normalized,
                  versionValue: normalized,
                },
              )
            ) {
              markTruncated();
              return { truncated: true };
            }
          }
        }
      }

      if (tag.tagName === "script" || tag.tagName === "style") {
        const close = new RegExp(`<\\/\\s*${tag.tagName}\\s*>`, "ig");
        close.lastIndex = index;
        const closing = close.exec(html);
        if (!closing) return { truncated: false };
        index = close.lastIndex;
      }
    }
    if (tagCount >= MAX_HTML_TAGS) markTruncated();
    return { truncated: tagCount >= MAX_HTML_TAGS };
  }
}
