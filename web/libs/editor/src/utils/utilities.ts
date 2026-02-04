import { formatDistanceToNow } from "date-fns";
import { destroy, detach } from "mobx-state-tree";
import { toCamelCase } from "strman";

/**
 * Internal helper to check if parameter is a string
 * @param {*} value
 * @returns {boolean}
 */
export const isString = (value: any): value is string => {
  return typeof value === "string" || value instanceof String;
};

/**
 * Internal helper to check if string is empty
 * @param {*} value
 * @returns {boolean}
 */
export const isStringEmpty = (value: string) => {
  if (!isString(value)) {
    return false;
  }

  return value.length === 0;
};

/**
 * Internal helper to check if string is JSON
 * @param {string} value
 * @returns {boolean}
 */
export const isStringJSON = (value: string) => {
  if (isString(value)) {
    try {
      JSON.parse(value);
    } catch (e) {
      return false;
    }

    return true;
  }

  return false;
};

/**
 * Check if text is url
 * @param {*} i
 * @param {*} text
 */
export function getUrl(i: number, text: string) {
  const stringToTest = text.slice(i);
  const myRegexp = /^(https?:\/\/(?:www\.|(?!www))[^\s\.]+\.[^\s]{2,}|www\.[^\s]+\.[^\s]{2,})/g; // eslint-disable-line no-useless-escape
  const match = myRegexp.exec(stringToTest);

  return match && match.length ? match[1] : "";
}

/**
 * Check if an IP address is in a private/internal range (SSRF protection)
 * Blocks: localhost, private networks, link-local, AWS metadata, and other internal addresses
 * @param {string} hostname - Hostname or IP address to check
 * @returns {boolean} true if the IP is private/internal and should be blocked
 */
export function isPrivateOrInternalIP(hostname: string): boolean {
  // Normalize hostname to lowercase for comparison
  const normalizedHost = hostname.toLowerCase();

  // Block localhost variants
  if (
    normalizedHost === "localhost" ||
    normalizedHost === "localhost." ||
    normalizedHost.endsWith(".localhost") ||
    normalizedHost.endsWith(".localhost.")
  ) {
    return true;
  }

  // Check for IPv6 localhost
  if (normalizedHost === "[::1]" || normalizedHost === "::1") {
    return true;
  }

  // Parse IPv4 addresses
  const ipv4Match = normalizedHost.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (ipv4Match) {
    const octets = ipv4Match.slice(1, 5).map(Number);

    // Validate octets are in range
    if (octets.some((o) => o > 255)) {
      return true; // Invalid IP, block it
    }

    const [a, b, c, d] = octets;

    // 127.0.0.0/8 - Loopback
    if (a === 127) return true;

    // 10.0.0.0/8 - Private Class A
    if (a === 10) return true;

    // 172.16.0.0/12 - Private Class B
    if (a === 172 && b >= 16 && b <= 31) return true;

    // 192.168.0.0/16 - Private Class C
    if (a === 192 && b === 168) return true;

    // 169.254.0.0/16 - Link-local (includes AWS metadata at 169.254.169.254)
    if (a === 169 && b === 254) return true;

    // 0.0.0.0/8 - Current network
    if (a === 0) return true;

    // 100.64.0.0/10 - Carrier-grade NAT
    if (a === 100 && b >= 64 && b <= 127) return true;

    // 192.0.0.0/24 - IETF Protocol Assignments
    if (a === 192 && b === 0 && c === 0) return true;

    // 192.0.2.0/24 - TEST-NET-1
    if (a === 192 && b === 0 && c === 2) return true;

    // 198.51.100.0/24 - TEST-NET-2
    if (a === 198 && b === 51 && c === 100) return true;

    // 203.0.113.0/24 - TEST-NET-3
    if (a === 203 && b === 0 && c === 113) return true;

    // 224.0.0.0/4 - Multicast
    if (a >= 224 && a <= 239) return true;

    // 240.0.0.0/4 - Reserved for future use
    if (a >= 240) return true;
  }

  // Check for IPv6 private addresses (simplified check)
  if (normalizedHost.startsWith("[") || normalizedHost.includes(":")) {
    const ipv6 = normalizedHost.replace(/^\[|\]$/g, "").toLowerCase();

    // Loopback (::1)
    if (ipv6 === "::1" || ipv6 === "0:0:0:0:0:0:0:1") return true;

    // Unspecified (::)
    if (ipv6 === "::" || ipv6 === "0:0:0:0:0:0:0:0") return true;

    // Link-local (fe80::/10)
    if (ipv6.startsWith("fe8") || ipv6.startsWith("fe9") || ipv6.startsWith("fea") || ipv6.startsWith("feb"))
      return true;

    // Unique local (fc00::/7)
    if (ipv6.startsWith("fc") || ipv6.startsWith("fd")) return true;

    // IPv4-mapped IPv6 addresses (::ffff:x.x.x.x) - check the embedded IPv4
    const ipv4MappedMatch = ipv6.match(/^::ffff:(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/i);
    if (ipv4MappedMatch) {
      const embeddedIPv4 = ipv4MappedMatch.slice(1).join(".");
      return isPrivateOrInternalIP(embeddedIPv4);
    }
  }

  // Block common cloud metadata hostnames
  const blockedHostnames = [
    "metadata.google.internal",
    "metadata.goog",
    "kubernetes.default.svc",
    "kubernetes.default",
    "kubernetes",
  ];
  if (blockedHostnames.includes(normalizedHost)) {
    return true;
  }

  return false;
}

/**
 * Validates a URL for SSRF protection
 * @param {string} urlString - URL to validate
 * @returns {{ isValid: boolean, error?: string }} Validation result
 */
export function validateUrlForSSRF(urlString: string): { isValid: boolean; error?: string } {
  try {
    const url = new URL(urlString);

    // Only allow http and https protocols
    if (url.protocol !== "http:" && url.protocol !== "https:") {
      return { isValid: false, error: "Only HTTP and HTTPS protocols are allowed" };
    }

    // Block URLs with credentials
    if (url.username || url.password) {
      return { isValid: false, error: "URLs with credentials are not allowed" };
    }

    // Check if hostname is a private/internal IP
    if (isPrivateOrInternalIP(url.hostname)) {
      return { isValid: false, error: "Access to internal/private addresses is not allowed" };
    }

    // Block uncommon ports that might be used for internal service discovery
    const port = url.port ? parseInt(url.port, 10) : url.protocol === "https:" ? 443 : 80;
    const allowedPorts = [80, 443, 8080, 8443];
    if (!allowedPorts.includes(port)) {
      return { isValid: false, error: `Port ${port} is not allowed` };
    }

    return { isValid: true };
  } catch (e) {
    return { isValid: false, error: "Invalid URL format" };
  }
}

/**
 * Check if given string is a valid url for object data (with SSRF protection)
 * @param {string} str              - String to check
 * @param {boolean} [relative=true] - Whether relative urls are good or not
 */
export function isValidObjectURL(str: string, relative = false) {
  if (typeof str !== "string") return false;
  if (relative && str.startsWith("/")) return true;
  if (!/^https?:\/\//.test(str)) return false;

  // Apply SSRF protection for absolute URLs
  const validation = validateUrlForSSRF(str);
  return validation.isValid;
}

/**
 * Convert MS to Time String
 * Example: 2000 -> 00:00:02
 * @param {number} ms
 * @returns {string}
 */
export function toTimeString(ms: number) {
  if (typeof ms === "number") {
    return new Date(ms).toUTCString().match(/(\d\d:\d\d:\d\d)/)?.[0];
  }
}

export function flatten(arr: any[]): any[] {
  return arr.reduce<any>(
    (flat, toFlatten) => flat.concat(Array.isArray(toFlatten) ? flatten(toFlatten) : toFlatten),
    [],
  );
}

export function hashCode(str: string) {
  let hash = 0;

  if (str.length === 0) {
    return `${hash}`;
  }
  for (let i = 0; i < str.length; i++) {
    const char = str.charCodeAt(i);

    hash = (hash << 5) - hash + char;
    hash = hash & hash; // Convert to 32bit integer
  }
  return `${hash}`;
}

export function atobUnicode(str: string) {
  // Going backwards: from bytestream, to percent-encoding, to original string.
  return decodeURIComponent(
    atob(str)
      .split("")
      .map((c) => `%${`00${c.charCodeAt(0).toString(16)}`.slice(-2)}`)
      .join(""),
  );
}

/**
 * Makes string safe to use inside dangerouslySetInnerHTML
 * @param {string} unsafe
 */
export function escapeHtml(unsafe: string) {
  return (unsafe ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

/**
 * Compares two arrays; order matters
 * @template T
 * @param {T[]} arr1 array 1
 * @param {T[]} arr2 array 2
 */
export function isArraysEqual(arr1: any[], arr2: any[]) {
  return arr1.length === arr2.length && arr1.every((value, index) => arr2[index] === value);
}

/**
 * Convert any value to an array
 * @template T
 * @param {T} value
 * @returns {T[]}
 */
export function wrapArray(value: any[]) {
  return ([] as any[]).concat(...[value]);
}

export function delay(ms = 0) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export const isDefined = <T>(value: T | null | undefined): value is T => {
  return value !== null && value !== undefined;
};

type ClosestParentPredicate<T> = (el: T) => boolean;
type ClosestParentGetter<T> = (el: T) => T;

export function findClosestParent<T extends { parent: any }>(
  el: T,
  predicate: ClosestParentPredicate<T> = () => true,
  parentGetter: ClosestParentGetter<T> = (el) => el.parent,
) {
  while ((el = parentGetter(el))) {
    if (predicate(el)) {
      return el;
    }
  }
  return null;
}

export function clamp(x: number, min: number, max: number) {
  return Math.min(max, Math.max(min, x));
}

export const chunks = <T extends any[]>(source: T, chunkSize: number): T[][] => {
  const result = [];
  let i;
  let j;

  for (i = 0, j = source.length; i < j; i += chunkSize) {
    result.push(source.slice(i, i + chunkSize));
  }

  return result;
};

export const userDisplayName = (user: Record<string, string> = {}) => {
  const { firstName, lastName } = user;

  return firstName || lastName
    ? [firstName, lastName]
        .filter((n) => !!n)
        .join(" ")
        .trim()
    : user.username || user.email;
};

/**
 * This name supposed to be username, but most likely it's first_name and last_name
 * @param {string} createdBy string like "[<name> ]<email>, <id>"
 * @returns {string} email
 */
export const emailFromCreatedBy = (createdBy: string) => {
  // get the email followed by id and cut off the id
  return createdBy?.match(/([^@,\s]+@[^@,\s]+)(,\s*\d+)?$/)?.[1];
};

export const camelizeKeys = (object: any): Record<string, unknown> => {
  return Object.fromEntries(
    Object.entries(object).map(([key, value]) => {
      if (Object.prototype.toString.call(value) === "[object Object]") {
        return [toCamelCase(key), camelizeKeys(value)];
      }
      return [toCamelCase(key), value];
    }),
  );
};

export function minMax(items: number[]) {
  return items.reduce<number[]>((acc, val) => {
    acc[0] = acc[0] === undefined || val < acc[0] ? val : acc[0];
    acc[1] = acc[1] === undefined || val > acc[1] ? val : acc[1];
    return acc;
  }, []);
}

// Detects if current OS is macOS
export function isMacOS() {
  return navigator.platform.indexOf("Mac") > -1;
}

export const triggerResizeEvent = () => {
  const event = new Event("resize");

  event.initEvent("resize", false, false);
  window.dispatchEvent(event);
};

export const humanDateDiff = (date: string | number): string => {
  const fnsDate = formatDistanceToNow(new Date(date), { addSuffix: true });

  if (fnsDate === "less than a minute ago") return "just now";
  return fnsDate;
};

export const destroyMSTObject = (object: any) => {
  if (object) {
    detach(object);
    destroy(object);
  }
};

// fixes `observe` - it watches only the changes of primitive props of observables used,
// so pass all the required primitives to this stub and they'll be observed
export const fixMobxObserve = (..._toObserve: any[]) => {};

/**
 * Sort annotations by createdDate in place. This function mutates the input array, so don't pass original list.
 * Use the same ordering in different places to keep it consistent. Just sort to have the latest first.
 * @param {object[]} annotations
 * @returns {object[]} sorted list of annotations
 */
export const sortAnnotations = (annotations: any[]) => {
  return annotations.sort((a, b) => new Date(b.createdDate).getTime() - new Date(a.createdDate).getTime());
};
