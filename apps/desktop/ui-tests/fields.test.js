// Tests for the custom-fields editor logic. Kept out of ui/ because that
// directory is the app's frontendDist and ships inside the bundle.
//
// Run with: node --test apps/desktop/ui-tests/
const test = require("node:test");
const assert = require("node:assert");
const fs = require("node:fs");
const path = require("node:path");
const {
  formFieldsFrom,
  newFormField,
  valueEdited,
  secretToggled,
  rowsNeedingAValue,
  submittedFields,
} = require("../ui/fields.js");

/// What the list hands the edit form: hidden values are withheld.
const stored = {
  fields: [
    { id: "aa01", label: "Account number", value: "12345678", secret: false, has_value: true },
    { id: "bb02", label: "Recovery code", value: "", secret: true, has_value: true },
    { id: "cc03", label: "Recovery code", value: "", secret: true, has_value: true },
  ],
};

test("hidden rows arrive kept and remember which stored field they are", () => {
  const rows = formFieldsFrom(stored);
  assert.deepStrictEqual(rows.map((r) => r.kept), [false, true, true]);
  assert.deepStrictEqual(rows.map((r) => r.id), ["aa01", "bb02", "cc03"]);
  assert.deepStrictEqual(formFieldsFrom(null), []);
  assert.strictEqual(newFormField().id, null, "a new row has no stored value behind it");
});

test("clearing a hidden row's box again means 'leave it alone', not 'delete it'", () => {
  // A keystroke typed and undone must not destroy a value nobody can see.
  const row = formFieldsFrom(stored)[1];
  const typed = valueEdited(row, "x");
  assert.strictEqual(typed.kept, false, "typing replaces the stored value");
  const cleared = valueEdited(typed, "");
  assert.strictEqual(cleared.kept, true, "emptying it again restores 'unchanged'");
  assert.strictEqual(submittedFields([cleared])[0].value, null);
  assert.strictEqual(submittedFields([typed])[0].value, "x");
});

test("clearing a visible row's box really does empty it", () => {
  // Its value was on screen, so the user can mean to delete it.
  const visible = formFieldsFrom(stored)[0];
  const cleared = valueEdited(visible, "");
  assert.strictEqual(cleared.kept, false);
  assert.strictEqual(submittedFields([cleared])[0].value, "");
});

test("revealing a stored hidden row ends its claim on the value for good", () => {
  const row = formFieldsFrom(stored)[1];
  const shown = secretToggled(row, false);
  assert.strictEqual(shown.kept, false);
  assert.strictEqual(shown.storedHidden, false, "the claim must not survive the reveal");
  assert.strictEqual(secretToggled(row, true), row, "toggling to the same state changes nothing");

  // Hide off then on again is a no-op in the user's mind. It must not leave a
  // row that looks unchanged but submits an empty value over the stored one.
  const reHidden = secretToggled(shown, true);
  assert.strictEqual(reHidden.kept, false);
  assert.deepStrictEqual(rowsNeedingAValue([reHidden]), [{ index: 0, label: "Recovery code" }], "saving this must be refused, not silent");

  // And after a reveal, emptying the box must not resurrect the claim: that
  // kept the stored value while displaying it in clear.
  const typed = valueEdited(shown, "x");
  const cleared = valueEdited(typed, "");
  assert.strictEqual(cleared.kept, false, "a revealed row cannot re-enter kept");
  assert.strictEqual(submittedFields([cleared])[0].value, "", "it carries its own value now");
  assert.deepStrictEqual(rowsNeedingAValue([cleared]), [{ index: 0, label: "Recovery code" }]);
});

test("an invisible space must not pass for a value", () => {
  // The box is masked for these rows, so a stray space renders as a password
  // dot: indistinguishable from empty. It drops the claim, so without this
  // it would both escape the guard and overwrite the stored value with " ".
  const row = formFieldsFrom(stored)[1];
  for (const blank of [" ", "   ", "\t", "\n "]) {
    const spaced = valueEdited(row, blank);
    assert.deepStrictEqual(
      rowsNeedingAValue([spaced]),
      [{ index: 0, label: "Recovery code" }],
      `${JSON.stringify(blank)} must not overwrite a value nobody has seen`,
    );
  }
  // A value with real content either side of a space is a value.
  assert.deepStrictEqual(rowsNeedingAValue([valueEdited(row, " a ")]), []);
});

test("the guard names every offending row and says where each one is", () => {
  const rows = formFieldsFrom(stored);
  rows[1] = valueEdited(rows[1], " ");
  rows[2] = secretToggled(rows[2], false);
  assert.deepStrictEqual(rowsNeedingAValue(rows), [
    { index: 1, label: "Recovery code" },
    { index: 2, label: "Recovery code" },
  ]);
});

test("a hidden field with nothing stored is not treated as precious", () => {
  // Its value is blank because it IS blank, not because it was withheld.
  // Treating it like an unseen secret made un-hiding it a permanent dead
  // end, refused on the grounds that it would erase something that is
  // not there.
  const empty = { fields: [{ id: "dd04", label: "Note", value: "", secret: true, has_value: false }] };
  const row = formFieldsFrom(empty)[0];
  assert.strictEqual(row.kept, false, "there is no value to keep");
  assert.deepStrictEqual(rowsNeedingAValue([row]), [], "and nothing to refuse");
  assert.strictEqual(submittedFields([row])[0].value, "");
  // Un-hiding it works, which is the whole point.
  const shown = secretToggled(row, false);
  assert.deepStrictEqual(rowsNeedingAValue([shown]), []);
});

test("a row that must be refused is only one that gave up an unseen value", () => {
  const rows = formFieldsFrom(stored);
  assert.deepStrictEqual(rowsNeedingAValue(rows), [], "untouched rows are fine");
  // A visible row emptied on purpose is fine: its value was on screen.
  assert.deepStrictEqual(rowsNeedingAValue([valueEdited(rows[0], "")]), []);
  // A brand-new empty row is fine; it is dropped rather than refused.
  assert.deepStrictEqual(rowsNeedingAValue([newFormField()]), []);
  // A revealed row with a real value typed in is fine.
  const refilled = valueEdited(secretToggled(rows[1], false), "typed-anew");
  assert.deepStrictEqual(rowsNeedingAValue([refilled]), []);
  assert.strictEqual(submittedFields([refilled])[0].value, "typed-anew");
});

test("a kept row whose label was blanked is submitted, not silently dropped", () => {
  const rows = formFieldsFrom(stored);
  rows[1].label = "";
  const out = submittedFields(rows);
  assert.strictEqual(out.length, 3, "no row may disappear on its way to the backend");
  assert.strictEqual(out[1].id, "bb02", "it still says which stored value it meant");
});

test("a row the user actually emptied is dropped", () => {
  assert.deepStrictEqual(submittedFields([newFormField()]), []);
  // One with only a value typed is kept, so the backend can name the missing
  // label rather than the row vanishing.
  assert.strictEqual(submittedFields([{ ...newFormField(), value: "4321" }]).length, 1);
});

test("each kept row names its own stored value, not the first of its name", () => {
  const rows = formFieldsFrom(stored);
  rows.splice(1, 1); // delete the FIRST of the two identically named rows
  assert.deepStrictEqual(submittedFields(rows).map((r) => r.id), ["aa01", "cc03"]);

  // Reordering carries each row's identity with it.
  const swapped = formFieldsFrom(stored);
  [swapped[1], swapped[2]] = [swapped[2], swapped[1]];
  assert.deepStrictEqual(submittedFields(swapped).map((r) => r.id), ["aa01", "cc03", "bb02"]);
});

test("renaming a hidden row keeps its value", () => {
  const rows = formFieldsFrom(stored);
  rows[1].label = "Backup code";
  const out = submittedFields(rows)[1];
  assert.deepStrictEqual(out, { id: "bb02", label: "Backup code", value: null, secret: true });
});

test("labels are trimmed and a brand-new row carries its value", () => {
  const rows = [{ ...newFormField(), label: "  PIN  ", value: "4321", secret: true }];
  assert.deepStrictEqual(submittedFields(rows), [{ id: null, label: "PIN", value: "4321", secret: true }]);
});

/// The Rust side reads this file back, so both halves are pinned to one
/// artefact instead of to a transcript copied between them by hand.
test("the checked-in payload fixture still matches what the editor produces", () => {
  const created = submittedFields([
    { ...newFormField(), label: "Account number", value: "99887766", secret: false },
    { ...newFormField(), label: "PIN", value: "4321", secret: true },
  ]);
  const editRows = formFieldsFrom(stored);
  editRows.splice(1, 1); // the delete-one-of-two case
  // A visible field emptied on purpose, so the fixture carries the
  // erase-versus-keep boundary (`""` against `null`) that is the whole point
  // of the contract, rather than only one side of it.
  editRows[0] = valueEdited(editRows[0], "");
  const fixture = {
    created: { name: "Email", username: "jude@example.com", password: "brand-new-password", url: "", notes: "", fields: created },
    edited: { name: "Bank", username: "jude", password: null, url: "https://bank.example.com", notes: "", fields: submittedFields(editRows) },
  };
  const out = path.join(__dirname, "testdata", "submitted_fields.json");
  const text = JSON.stringify(fixture, null, 2) + "\n";
  if (process.env.UPDATE_FIXTURES) {
    fs.writeFileSync(out, text);
    return;
  }
  // Compared, not written: writing it would make this test pass by
  // definition and let the committed file drift from the code that produces
  // it, with the Rust half validating whatever happened to be on disk.
  // Re-generate deliberately with UPDATE_FIXTURES=1.
  assert.strictEqual(
    fs.readFileSync(out, "utf8"),
    text,
    "the checked-in fixture is stale; re-run with UPDATE_FIXTURES=1 and commit it",
  );
});
