/**
 * URL Security Utilities
 * Provides safe URL validation and redirect functions to prevent open redirect vulnerabilities.
 */

/**
 * Validates if a URL is safe for redirection.
 * Safe URLs are:
 * - Relative paths starting with "/" (but not "//")
 * - Relative paths without leading slash (same-origin relative)
 * - Absolute URLs to the same origin
 *
 * Unsafe URLs are:
 * - javascript: protocol URLs
 * - vbscript: protocol URLs
 * - data: protocol URLs
 * - Protocol-relative URLs (//example.com)
 * - Absolute URLs to different origins
 *
 * @param url - The URL to validate
 * @returns Whether the URL is safe for redirection
 */
export const isUrlSafe = (url: string | null | undefined): boolean => {
  if (!url || typeof url !== "string") {
    return false;
  }

  const trimmedUrl = url.trim();
  if (!trimmedUrl) {
    return false;
  }

  // Block javascript:, vbscript:, and data: protocols
  const lowerUrl = trimmedUrl.toLowerCase();
  if (lowerUrl.startsWith("javascript:")) {
    return false;
  }

  if (lowerUrl.startsWith("vbscript:")) {
    return false;
  }

  if (lowerUrl.startsWith("data:")) {
    return false;
  }

  // Block protocol-relative URLs (//example.com)
  if (trimmedUrl.startsWith("//")) {
    return false;
  }

  // Allow relative paths starting with / (but not //)
  if (trimmedUrl.startsWith("/") && !trimmedUrl.startsWith("//")) {
    return true;
  }

  // Allow relative paths starting with ./ or ../
  if (trimmedUrl.startsWith("./") || trimmedUrl.startsWith("../")) {
    return true;
  }

  // Allow query strings and hash fragments for current page
  if (trimmedUrl.startsWith("?") || trimmedUrl.startsWith("#")) {
    return true;
  }

  // For absolute URLs, verify same origin
  try {
    const parsedUrl = new URL(trimmedUrl, window.location.origin);
    return parsedUrl.origin === window.location.origin;
  } catch (e) {
    // If URL parsing fails, it might be a relative path without leading /
    // Check if it looks like a relative path (no protocol)
    if (!trimmedUrl.includes(":")) {
      return true;
    }
    return false;
  }
};

/**
 * Safely redirect to a URL after validation.
 * If the URL is unsafe, redirects to a fallback URL instead.
 *
 * @param url - The URL to redirect to
 * @param fallbackUrl - The fallback URL if validation fails (default: "/")
 * @returns Whether the redirect was to the original URL (true) or fallback (false)
 */
export const safeRedirect = (url: string, fallbackUrl: string = "/"): boolean => {
  // Validate fallback URL to prevent bypass
  if (!fallbackUrl || !isUrlSafe(fallbackUrl)) {
    fallbackUrl = "/";
  }
  if (isUrlSafe(url)) {
    window.location.href = url;
    return true;
  }
  console.warn("Blocked unsafe redirect to:", url);
  window.location.href = fallbackUrl;
  return false;
};

/**
 * Safely navigate by assigning to window.location.
 * If the URL is unsafe, navigates to a fallback URL instead.
 *
 * @param url - The URL to navigate to
 * @param fallbackUrl - The fallback URL if validation fails (default: "/")
 * @returns Whether navigation was to the original URL (true) or fallback (false)
 */
export const safeNavigate = (url: string, fallbackUrl: string = "/"): boolean => {
  // Validate fallback URL to prevent bypass
  if (!fallbackUrl || !isUrlSafe(fallbackUrl)) {
    fallbackUrl = "/";
  }
  if (isUrlSafe(url)) {
    window.location.href = url;
    return true;
  }
  console.warn("Blocked unsafe navigation to:", url);
  window.location.href = fallbackUrl;
  return false;
};

/**
 * Safely open a URL in a new window/tab after validation.
 * If the URL is unsafe, does not open anything.
 *
 * @param url - The URL to open
 * @param target - The window target (default: "_blank")
 * @param features - Window features string
 * @returns The window object if opened, null if blocked
 */
export const safeWindowOpen = (
  url: string,
  target: string = "_blank",
  features: string = ""
): Window | null => {
  if (isUrlSafe(url)) {
    return window.open(url, target, features);
  }
  console.warn("Blocked unsafe window.open to:", url);
  return null;
};

/**
 * Sanitize a URL for display or use in href attributes.
 * Returns the original URL if safe, or a safe fallback otherwise.
 *
 * @param url - The URL to sanitize
 * @param fallbackUrl - The fallback URL if validation fails (default: "#")
 * @returns The sanitized URL
 */
export const sanitizeUrl = (url: string, fallbackUrl: string = "#"): string => {
  // Validate fallback URL to prevent bypass
  if (!fallbackUrl || !isUrlSafe(fallbackUrl)) {
    fallbackUrl = "#";
  }
  if (isUrlSafe(url)) {
    return url;
  }
  return fallbackUrl;
};
