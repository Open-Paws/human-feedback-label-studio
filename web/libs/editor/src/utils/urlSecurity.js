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
 * - data: protocol URLs
 * - Protocol-relative URLs (//example.com)
 * - Absolute URLs to different origins
 *
 * @param {string} url - The URL to validate
 * @returns {boolean} - Whether the URL is safe for redirection
 */
export const isUrlSafe = (url) => {
  if (!url || typeof url !== "string") {
    return false;
  }

  const trimmedUrl = url.trim();
  if (!trimmedUrl) {
    return false;
  }

  // Block javascript: protocol
  if (trimmedUrl.toLowerCase().startsWith("javascript:")) {
    return false;
  }

  // Block data: protocol
  if (trimmedUrl.toLowerCase().startsWith("data:")) {
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
 * @param {string} url - The URL to redirect to
 * @param {string} fallbackUrl - The fallback URL if validation fails (default: "/")
 * @returns {boolean} - Whether the redirect was to the original URL (true) or fallback (false)
 */
export const safeRedirect = (url, fallbackUrl = "/") => {
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
 * @param {string} url - The URL to navigate to
 * @param {string} fallbackUrl - The fallback URL if validation fails (default: "/")
 * @returns {boolean} - Whether navigation was to the original URL (true) or fallback (false)
 */
export const safeNavigate = (url, fallbackUrl = "/") => {
  if (isUrlSafe(url)) {
    window.location = url;
    return true;
  }
  console.warn("Blocked unsafe navigation to:", url);
  window.location = fallbackUrl;
  return false;
};

/**
 * Safely open a URL in a new window/tab after validation.
 * If the URL is unsafe, does not open anything.
 *
 * @param {string} url - The URL to open
 * @param {string} target - The window target (default: "_blank")
 * @param {string} features - Window features string
 * @returns {Window|null} - The window object if opened, null if blocked
 */
export const safeWindowOpen = (url, target = "_blank", features = "") => {
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
 * @param {string} url - The URL to sanitize
 * @param {string} fallbackUrl - The fallback URL if validation fails (default: "#")
 * @returns {string} - The sanitized URL
 */
export const sanitizeUrl = (url, fallbackUrl = "#") => {
  if (isUrlSafe(url)) {
    return url;
  }
  return fallbackUrl;
};
