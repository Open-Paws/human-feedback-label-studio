import { getRoot, types } from "mobx-state-tree";

const PersistentStateMixin = types
  .model({})
  .views(() => ({
    get persistentValuesKey() {
      return "labelStudio:storedValues";
    },

    get persistentValues() {
      return {};
    },
  }))
  .actions((self) => ({
    afterCreate() {
      setTimeout(self.restoreValues);
    },

    beforeDestroy() {
      self.storeValues();
    },

    storeValues() {
      const key = self.persistentValuesKey;
      const obj = { task: getRoot(self).task?.id, values: self.persistentValues };

      localStorage.setItem(key, JSON.stringify(obj));
    },

    restoreValues() {
      const stored = JSON.parse(localStorage.getItem(self.persistentValuesKey) || "{}");

      if (!stored || stored.task !== getRoot(self).task?.id) return;
      const values = stored.values || {};

      // Security: Get the allowed keys from persistentValues view to prevent property injection
      const allowedKeys = Object.keys(self.persistentValues || {});

      for (const key of Object.keys(values)) {
        // Security: Only restore values that are in the whitelist of persistent values
        if (allowedKeys.includes(key) && Object.prototype.hasOwnProperty.call(self, key)) {
          self[key] = values[key];
        }
      }
    },
  }));

export default PersistentStateMixin;
