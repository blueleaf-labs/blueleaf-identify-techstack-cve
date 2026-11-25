import type { FingerprintDefinitionSet } from "../domain/fingerprints.js";

/** Built-in, versioned fingerprint knowledge. Signatures are literal data, not executable code. */
export const BUILTIN_FINGERPRINT_DEFINITIONS: FingerprintDefinitionSet = {
  schemaVersion: "1.0",
  definitions: [
    {
      id: "php",
      displayName: "PHP",
      category: "programming-language",
      minimumConfidence: 0.25,
      singleSignalConfidenceCap: 0.72,
      signals: [
        {
          id: "x-powered-by-php",
          evidenceTypes: ["header"],
          keys: ["x-powered-by"],
          operator: "prefix",
          value: "php",
          weight: 0.84,
          reason:
            "The X-Powered-By header names PHP; this configurable header can be spoofed or rewritten by a proxy.",
        },
        {
          id: "php-session-cookie",
          evidenceTypes: ["cookie"],
          keys: ["phpsessid"],
          operator: "equals",
          value: "phpsessid=<redacted>",
          weight: 0.56,
          reason:
            "A PHP session cookie name was observed; cookie names can be customized or imitated.",
        },
        {
          id: "php-generator",
          evidenceTypes: ["html-generator"],
          operator: "prefix",
          value: "php",
          weight: 0.66,
          reason:
            "The HTML generator metadata mentions PHP; generator values are self-reported and may be stale.",
        },
      ],
    },
    {
      id: "nginx",
      displayName: "nginx",
      category: "web-server",
      minimumConfidence: 0.25,
      singleSignalConfidenceCap: 0.72,
      contradicts: ["apache"],
      signals: [
        {
          id: "server-header-nginx",
          evidenceTypes: ["header"],
          keys: ["server"],
          operator: "contains",
          value: "nginx",
          weight: 0.82,
          reason:
            "The Server header names nginx; server headers are configurable and may identify a reverse proxy or CDN edge.",
        },
        {
          id: "via-header-nginx",
          evidenceTypes: ["header"],
          keys: ["via"],
          operator: "contains",
          value: "nginx",
          weight: 0.38,
          reason:
            "A Via header mentions nginx, which may describe an intermediary rather than the origin server.",
        },
        {
          id: "backend-header-nginx",
          evidenceTypes: ["header"],
          keys: ["x-backend-server", "x-served-by"],
          operator: "contains",
          value: "nginx",
          weight: 0.48,
          reason:
            "A backend or served-by header mentions nginx; this custom header may be supplied by an intermediary.",
        },
        {
          id: "nginx-generator",
          evidenceTypes: ["html-generator"],
          operator: "contains",
          value: "nginx",
          weight: 0.42,
          reason:
            "The HTML generator metadata mentions nginx; this is a self-reported hint.",
        },
      ],
    },
    {
      id: "apache",
      displayName: "Apache HTTP Server",
      category: "web-server",
      minimumConfidence: 0.25,
      singleSignalConfidenceCap: 0.72,
      contradicts: ["nginx"],
      signals: [
        {
          id: "server-header-apache",
          evidenceTypes: ["header"],
          keys: ["server"],
          operator: "contains",
          value: "apache",
          weight: 0.82,
          reason:
            "The Server header names Apache; server headers are configurable and may identify a reverse proxy or CDN edge.",
        },
        {
          id: "server-header-httpd",
          evidenceTypes: ["header"],
          keys: ["server"],
          operator: "contains",
          value: "httpd",
          weight: 0.78,
          reason:
            "The Server header contains the common httpd token; it can be configured or supplied by an intermediary.",
        },
        {
          id: "backend-header-apache",
          evidenceTypes: ["header"],
          keys: ["x-backend-server", "x-served-by"],
          operator: "contains",
          value: "apache",
          weight: 0.48,
          reason:
            "A backend or served-by header mentions Apache; this custom header may be supplied by an intermediary.",
        },
        {
          id: "apache-generator",
          evidenceTypes: ["html-generator"],
          operator: "contains",
          value: "apache",
          weight: 0.42,
          reason:
            "The HTML generator metadata mentions Apache; this is a self-reported hint.",
        },
      ],
    },
  ],
};
