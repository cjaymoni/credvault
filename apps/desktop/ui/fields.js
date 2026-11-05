// Pure logic for the custom-fields editor, kept out of app.js so it can be
// exercised without a DOM. Loaded as an ordinary script by the app and
// required directly by the tests in ../ui-tests/.
//
// These rules decide whether a secret survives an edit, so every transition
// is tested, including the ones that follow another transition.
//
// A hidden field's value never reaches the UI, so a row standing for one is
// "kept": submitted with no value, leaving the stored one alone. Which stored
// value it means is decided by the field's id, never its label (several may
// share one) or its position (another device may have reordered them).
//
// Two flags, deliberately not one:
//
//   renderedHidden  fixed at render: this row arrived standing for a value
//                   nobody has seen. Never cleared, because that fact never
//                   stops being true of this editing session.
//   storedHidden    the live claim on that value. Cleared the moment the row
//                   stops standing for it, so the claim cannot come back.
//
// Collapsing them lets a revealed row re-acquire a claim it had given up, and
// a value the user marked sensitive is then kept while displayed in clear.
(function (root, factory) {
  if (typeof module === "object" && module.exports) module.exports = factory();
  else root.Fields = factory();
})(typeof self !== "undefined" ? self : globalThis, function () {
  /// Editor rows for a secret being edited, or none for a new one.
  function formFieldsFrom(existing) {
    return ((existing && existing.fields) || []).map((field) => ({
      id: field.id,
      label: field.label,
      value: field.value,
      secret: field.secret,
      // A hidden value never reached the UI, so it is kept unless retyped —
      // unless there is no value, in which case there is nothing to protect
      // and the row behaves like a visible one, editable and erasable.
      kept: field.secret && field.has_value !== false,
      storedHidden: field.secret && field.has_value !== false,
      renderedHidden: field.secret,
      hadValue: field.has_value !== false,
    }));
  }

  /// A blank row the user just added. It has no id until it is stored.
  function newFormField() {
    return {
      id: null,
      label: "",
      value: "",
      secret: false,
      kept: false,
      storedHidden: false,
      renderedHidden: false,
      hadValue: false,
    };
  }

  /// The value box was edited. Emptying it again re-enters kept, so a
  /// keystroke typed and undone does not destroy a value nobody can see —
  /// but only while this row still has a claim on that value.
  function valueEdited(field, typed) {
    return { ...field, value: typed, kept: Boolean(field.storedHidden) && typed === "" };
  }

  /// The Hide checkbox was toggled. A stored hidden value cannot be shown, so
  /// revealing the row ends its claim for good: it must not be able to
  /// re-enter kept from an empty box, nor to carry the stored value forward
  /// now that the row would display it in clear.
  function secretToggled(field, hidden) {
    if (hidden === field.secret) return field;
    // A claim exists only while `secret` is true, so reaching here at all —
    // the flag changed — means the row either had no claim or is giving it
    // up. Either way it ends, unconditionally. Written without a condition
    // because a condition here would read as if hiding could restore one.
    return { ...field, secret: hidden, kept: false, storedHidden: false };
  }

  /// Rows that arrived standing for an unseen value, gave up that claim, and
  /// have nothing typed in their place. Saving one would wipe a value that
  /// was never on screen, so the form refuses instead and names them.
  /// Returns each row's position too, so the form can send the user to the
  /// row it just named rather than to the first one.
  function rowsNeedingAValue(formFields) {
    // Trimmed, because the box is masked for these rows: a stray space is a
    // password dot, indistinguishable from an empty field, and it both drops
    // the claim and would otherwise slip past this guard.
    //
    // The index comes from the enumeration rather than a lookup, so two rows
    // that happen to be equal cannot resolve to the same one.
    return formFields.flatMap((field, index) =>
      field.renderedHidden && field.hadValue && !field.kept && field.value.trim() === ""
        ? [{ index, label: field.label.trim() || "an unnamed field" }]
        : [],
    );
  }

  /// What the form sends back. A kept value goes as null, which Rust reads as
  /// "leave the stored one alone", resolved by id.
  ///
  /// A row is dropped only when the user has actually emptied it. A kept row
  /// still stands for a value nobody has seen, so blanking its label must not
  /// discard it: it goes through and is refused by name instead. Removing a
  /// field is what the remove button is for.
  function submittedFields(formFields) {
    return formFields
      // Filtered on the rows themselves. Filtering the mapped objects tests a
      // `kept` that mapping has already dropped, which silently discarded
      // every kept row whose label had been blanked.
      .filter((field) => field.kept || field.label.trim() !== "" || field.value)
      .map((field) => ({
        id: field.id,
        label: field.label.trim(),
        value: field.kept ? null : field.value,
        secret: field.secret,
      }));
  }

  return { formFieldsFrom, newFormField, valueEdited, secretToggled, rowsNeedingAValue, submittedFields };
});
