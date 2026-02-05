import { flow, types } from "mobx-state-tree";
import Papa from "papaparse";

import { parseTypeAndOption, parseValue } from "../utils/data";
import { validateUrlForSSRF } from "../utils/utilities";

const resolvers = {
  // @todo comments/types
  csv(content, options = {}) {
    const header = !options.headless;
    const {
      data,
      meta: { fields },
    } = Papa.parse(content, { delimiter: options.separator, header });
    const { column = header ? fields[0] : 0 } = options;
    const row = data[0];
    let cell = row[column];

    if (cell === undefined) {
      // if `column` is a number even if csv has header
      cell = row[fields[column] ?? fields[0]];
    }

    return String(cell ?? "");
  },
};

const ProcessAttrsMixin = types
  .model({
    resolver: types.maybeNull(types.string),
  })
  .actions((self) => ({
    updateLocalValue(value) {
      self._value = value;
    },

    updateValue(store) {
      self._value = parseValue(self.value, store?.task?.dataObj ?? {});
    },

    /**
     * Use `resolver` param for data retrieval from remote resource
     * format: <type>(<separator>option=value)*
     * currently only csv type supported, separator is | by default
     */
    resolveValue: flow(function* (value) {
      if (!self.resolver) return value;

      const { type, options } = parseTypeAndOption(self.resolver);

      if (!Object.prototype.hasOwnProperty.call(resolvers, type)) {
        console.error(`Resolver "${type ?? self.resolver}" looks unfamiliar`);
        return value;
      }

      // SSRF protection: validate URL before fetching
      const urlValidation = validateUrlForSSRF(value);
      if (!urlValidation.isValid) {
        console.error("SSRF validation failed for URL");
        throw new Error("SSRF validation failed: URL is not allowed");
      }

      // Use redirect: 'error' to block automatic redirect following,
      // preventing attackers from redirecting to internal IPs after initial validation
      const response = yield fetch(value, { redirect: "error" });
      const text = yield response.text();

      return resolvers[type](text, options);
    }),
  }));

export default ProcessAttrsMixin;
