import { isDefined } from "./utils";

// Helper to check if a property name is safe (not a prototype pollution vector)
const isSafeKey = (key) => {
  const dangerousKeys = ["__proto__", "constructor", "prototype"];
  return typeof key === "string" && !dangerousKeys.includes(key);
};

export const History = {
  getParams(urlInstance) {
    const url = urlInstance ?? new URL(window.location.href);
    const result = {};

    url.searchParams.forEach((value, key) => {
      // Validate key to prevent prototype pollution
      if (isSafeKey(key)) {
        result[key] = value;
      }
    });

    return result;
  },

  setParams(params = {}) {
    const url = new URL(window.location.href);
    const { searchParams } = url;

    Object.entries(params).forEach(([key, value]) => {
      if (value === null || value === undefined) {
        searchParams.delete(key);
      } else {
        searchParams.set(key, value);
      }
    });

    return url;
  },

  navigate(params = {}, replace = false) {
    const url = this.setParams(params);
    const title = document.title;
    const state = this.getParams(url);

    if (replace) {
      window.history.replaceState(state, title, url.toString());
    } else {
      window.history.pushState(state, title, url.toString());
    }
  },

  forceNavigate(params = {}, replace = false) {
    const resultParams = params ?? {};
    const currentParams = this.getParams();

    Object.entries(currentParams).forEach(([key]) => {
      if (!isDefined(resultParams[key])) {
        resultParams[key] = null;
      }
    });

    if (currentParams.query) {
      resultParams.query = currentParams.query;
    }

    this.navigate(resultParams, replace);
  },
};
