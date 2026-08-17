// =============================================================
//  bw_json_parser.cpp  —  Streaming Bitwarden JSON export parser
//  (implementation — see bw_json_parser.h for the design overview)
// =============================================================
#include "bw_json_parser.h"

// ── Small helpers ─────────────────────────────────────────────────────
static void bwResetItem(BwParsedItem &it) {
  memset(&it, 0, sizeof(it));
}
static void bwResetFolder(BwParsedFolder &f) {
  memset(&f, 0, sizeof(f));
}

// Append one character into the current value buffer, respecting its cap.
// Never overruns — once valLen reaches BW_VAL_BUF_LEN-1, further bytes are
// silently dropped (valOverflowed is set for callers that care), but the
// state machine keeps consuming the string until its closing quote so
// parsing stays in sync.
static void bwValAppend(BwParserState &st, char c) {
  if (st.valLen + 1 < BW_VAL_BUF_LEN) {
    st.valBuf[st.valLen++] = c;
    st.valBuf[st.valLen] = 0;
  } else {
    st.valOverflowed = true;
  }
}

void bwParserInit(BwParserState &st) {
  memset(&st, 0, sizeof(st));
  st.state = BW_EXPECT_TOP_OBJ_OPEN;
  st.valState = BW_VAL_NONE;
  st.target = BW_TARGET_NONE;
  st.expectKey = true;
  bwResetItem(st.curItem);
  bwResetFolder(st.curFolder);
}

bool bwParserDone(const BwParserState &st)    { return st.state == BW_DONE; }
bool bwParserErrored(const BwParserState &st) { return st.errored; }

// Skip-buffer max caps applied per-target when accumulating a KNOWN field —
// each target has its own natural width via the struct field it writes
// into (bwValFlushInto below uses sizeof() on the destination), so no
// separate table is needed here.

// Commit the currently-accumulated valBuf into whichever target field is
// active, then reset the value accumulator for the next value.
static void bwValFlush(BwParserState &st) {
  switch (st.target) {
    case BW_TARGET_KEY:
      strncpy(st.keyBuf, st.valBuf, sizeof(st.keyBuf) - 1);
      st.keyBuf[sizeof(st.keyBuf) - 1] = 0;
      st.keyLen = (uint8_t)strlen(st.keyBuf);
      break;
    case BW_TARGET_ITEM_NAME:
      strncpy(st.curItem.title, st.valBuf, sizeof(st.curItem.title) - 1);
      break;
    case BW_TARGET_ITEM_NOTES: {
      // First contribution to noteAccum — no separator needed.
      size_t have = strlen(st.curItem.noteAccum);
      size_t room = sizeof(st.curItem.noteAccum) - have - 1;
      if (room > 0) strncat(st.curItem.noteAccum, st.valBuf, room);
      if (st.valBuf[0]) st.curItemHasNote = true;
      break;
    }
    case BW_TARGET_ITEM_FOLDERID:
      strncpy(st.curItem.bwFolderId, st.valBuf, sizeof(st.curItem.bwFolderId) - 1);
      break;
    case BW_TARGET_LOGIN_USERNAME:
      strncpy(st.curItem.username, st.valBuf, sizeof(st.curItem.username) - 1);
      break;
    case BW_TARGET_LOGIN_PASSWORD:
      strncpy(st.curItem.password, st.valBuf, sizeof(st.curItem.password) - 1);
      break;
    case BW_TARGET_LOGIN_TOTP: {
      if (st.valBuf[0]) {
        char line[BW_MAX_NOTE_ACCUM_LEN];
        snprintf(line, sizeof(line), "%s[TOTP] %s",
                st.curItemHasNote ? "\n" : "", st.valBuf);
        size_t have = strlen(st.curItem.noteAccum);
        size_t room = sizeof(st.curItem.noteAccum) - have - 1;
        if (room > 0) strncat(st.curItem.noteAccum, line, room);
        st.curItemHasNote = true;
      }
      break;
    }
    case BW_TARGET_URI_VALUE: {
      if (!st.curItem.url[0]) {
        // First/primary URI -> the real url field.
        strncpy(st.curItem.url, st.valBuf, sizeof(st.curItem.url) - 1);
      } else if (st.valBuf[0]) {
        // Extra URIs -> folded into notes (best-effort, may truncate —
        // see the documented note-field-size trade-off).
        char line[BW_MAX_NOTE_ACCUM_LEN];
        snprintf(line, sizeof(line), "%s[URL2] %s",
                st.curItemHasNote ? "\n" : "", st.valBuf);
        size_t have = strlen(st.curItem.noteAccum);
        size_t room = sizeof(st.curItem.noteAccum) - have - 1;
        if (room > 0) strncat(st.curItem.noteAccum, line, room);
        st.curItemHasNote = true;
      }
      break;
    }
    case BW_TARGET_FIELD_NAME:
      // Stash temporarily in keyBuf's sibling — reuse valBuf itself is
      // already the name; keep it until the field's value arrives by
      // copying into a dedicated slot via the field-object handling below.
      // (Handled directly in the item-object dispatch — see the
      // BW_IN_FIELD_OBJECT case, which reads valBuf right before reset.)
      break;
    case BW_TARGET_FIELD_VALUE:
      // Same — combined with the pending field NAME at the point the
      // field object closes (see the '}' handling for BW_IN_FIELD_OBJECT).
      break;
    case BW_TARGET_FOLDER_ID:
      strncpy(st.curFolder.bwId, st.valBuf, sizeof(st.curFolder.bwId) - 1);
      break;
    case BW_TARGET_FOLDER_NAME:
      strncpy(st.curFolder.name, st.valBuf, sizeof(st.curFolder.name) - 1);
      break;
    default:
      break;   // BW_TARGET_NONE — discard
  }
  st.valBuf[0] = 0;
  st.valLen = 0;
  st.valOverflowed = false;
  st.target = BW_TARGET_NONE;
}

// Pending custom-field name, held between "name" and "value" keys within
// one {"name":..,"value":..,"type":..} field object. Small, fixed, and
// reset per field object — doesn't need to be in BwParserState since a
// field object is always fully processed within known bounds before the
// next one starts (no cross-chunk-boundary risk beyond what valBuf already
// handles, since THIS buffer is only read/written at a single '}' point,
// never accumulated byte-by-byte itself).
static char s_pendingFieldName[BW_MAX_KEY_LEN + 8];
static char s_pendingFieldValue[BW_MAX_NOTE_ACCUM_LEN];

// ── Key dispatch tables (by current structural state) ────────────────────
// Returns the BwTarget for a known key, or BW_TARGET_NONE if unrecognized
// (caller then skips the value). `nextState`/`isObject`/`isArray` describe
// what to transition into if the value turns out to be a nested container.
struct KeyDispatch {
  const char *key;
  BwTarget    target;      // used when the value is a scalar (string/number/etc)
  BwState     nestState;   // used when the value is an object/array we recurse into (BW_ERROR = "never nests")
};

static const KeyDispatch TOP_KEYS[] = {
  {"encrypted", BW_TARGET_NONE, BW_ERROR},     // handled specially (see below)
  {"folders",   BW_TARGET_NONE, BW_IN_FOLDERS_ARRAY},
  {"items",     BW_TARGET_NONE, BW_IN_ITEMS_ARRAY},
};
static const KeyDispatch FOLDER_KEYS[] = {
  {"id",   BW_TARGET_FOLDER_ID,   BW_ERROR},
  {"name", BW_TARGET_FOLDER_NAME, BW_ERROR},
};
static const KeyDispatch ITEM_KEYS[] = {
  {"type",     BW_TARGET_ITEM_TYPE,     BW_ERROR},
  {"name",     BW_TARGET_ITEM_NAME,     BW_ERROR},
  {"notes",    BW_TARGET_ITEM_NOTES,    BW_ERROR},
  {"folderId", BW_TARGET_ITEM_FOLDERID, BW_ERROR},
  {"login",    BW_TARGET_NONE,          BW_IN_LOGIN_OBJECT},
  {"fields",   BW_TARGET_NONE,          BW_IN_FIELDS_ARRAY},
};
static const KeyDispatch LOGIN_KEYS[] = {
  {"username", BW_TARGET_LOGIN_USERNAME, BW_ERROR},
  {"password", BW_TARGET_LOGIN_PASSWORD, BW_ERROR},
  {"totp",     BW_TARGET_LOGIN_TOTP,     BW_ERROR},
  {"uris",     BW_TARGET_NONE,           BW_IN_URIS_ARRAY},
};
static const KeyDispatch URI_KEYS[] = {
  {"uri", BW_TARGET_URI_VALUE, BW_ERROR},
};
static const KeyDispatch FIELD_KEYS[] = {
  {"name",  BW_TARGET_FIELD_NAME,  BW_ERROR},
  {"value", BW_TARGET_FIELD_VALUE, BW_ERROR},
};

static const KeyDispatch *dispatchFor(BwState s, size_t &n) {
  switch (s) {
    case BW_IN_TOP_OBJECT:    n = sizeof(TOP_KEYS)/sizeof(TOP_KEYS[0]);     return TOP_KEYS;
    case BW_IN_FOLDER_OBJECT: n = sizeof(FOLDER_KEYS)/sizeof(FOLDER_KEYS[0]); return FOLDER_KEYS;
    case BW_IN_ITEM_OBJECT:   n = sizeof(ITEM_KEYS)/sizeof(ITEM_KEYS[0]);   return ITEM_KEYS;
    case BW_IN_LOGIN_OBJECT:  n = sizeof(LOGIN_KEYS)/sizeof(LOGIN_KEYS[0]); return LOGIN_KEYS;
    case BW_IN_URI_OBJECT:    n = sizeof(URI_KEYS)/sizeof(URI_KEYS[0]);    return URI_KEYS;
    case BW_IN_FIELD_OBJECT:  n = sizeof(FIELD_KEYS)/sizeof(FIELD_KEYS[0]); return FIELD_KEYS;
    default: n = 0; return nullptr;
  }
}

// Object-close targets: which state to pop BACK to when the CURRENT
// object's '}' is seen. Fixed by construction (max nesting depth 4, known
// schema — see file header), so a flat lookup is enough, no real stack.
static BwState parentOfObject(BwState s) {
  switch (s) {
    case BW_IN_FOLDER_OBJECT: return BW_IN_FOLDERS_ARRAY;
    case BW_IN_ITEM_OBJECT:   return BW_IN_ITEMS_ARRAY;
    case BW_IN_LOGIN_OBJECT:  return BW_IN_ITEM_OBJECT;
    case BW_IN_URI_OBJECT:    return BW_IN_URIS_ARRAY;
    case BW_IN_FIELD_OBJECT:  return BW_IN_FIELDS_ARRAY;
    default: return BW_ERROR;
  }
}
static BwState parentOfArray(BwState s) {
  switch (s) {
    case BW_IN_FOLDERS_ARRAY: return BW_IN_TOP_OBJECT;
    case BW_IN_ITEMS_ARRAY:   return BW_IN_TOP_OBJECT;
    case BW_IN_URIS_ARRAY:    return BW_IN_LOGIN_OBJECT;
    case BW_IN_FIELDS_ARRAY:  return BW_IN_ITEM_OBJECT;
    default: return BW_ERROR;
  }
}

// ── Main byte-driven state machine ───────────────────────────────────────
// One byte at a time — no recursion, no lookahead beyond the current byte
// plus the persistent escapePending flag. Every transition consumes
// exactly one byte, so the parser cannot hang or loop without making
// forward progress through the input.
static void bwFeedByte(BwParserState &st, uint8_t b,
                       BwOnItemFn onItem, void *itemCtx,
                       BwOnFolderFn onFolder, void *folderCtx) {
  if (st.errored) return;

  // ── Skipping an unrecognized value ─────────────────────────────────
  if (st.valState == BW_VAL_SKIP) {
    if (st.skipOpenChar == '"') {
      // Skipping a bare string value we don't care about.
      if (st.escapePending) { st.escapePending = false; return; }
      if (b == '\\') { st.escapePending = true; return; }
      if (b == '"') { st.valState = BW_VAL_NONE; bwValFlush(st); /* target NONE -> discard */ return; }
      return;
    }
    // Skipping an object/array (possibly containing nested strings/braces —
    // those must not perturb the depth counter while inside a string).
    if (st.escapePending) { st.escapePending = false; return; }
    if (b == '\\') { st.escapePending = true; return; }
    if (b == '"') { st.skipInString = !st.skipInString; return; }
    if (st.skipInString) return;   // inside a skipped string — ignore braces/brackets
    if (b == '{' || b == '[') {
      st.skipDepth++;
      if (st.skipDepth > BW_MAX_SKIP_DEPTH) { st.state = BW_ERROR; st.errored = true; }
      return;
    }
    if (b == '}' || b == ']') {
      st.skipDepth--;
      if (st.skipDepth <= 0) { st.valState = BW_VAL_NONE; st.target = BW_TARGET_NONE; }
      return;
    }
    return;
  }

  // ── Accumulating a string value ────────────────────────────────────
  if (st.valState == BW_VAL_STRING) {
    if (st.escapePending) {
      st.escapePending = false;
      char c = b;
      switch (b) {
        case 'n': c = '\n'; break;
        case 't': c = '\t'; break;
        case 'r': c = '\r'; break;
        case '"': c = '"';  break;
        case '\\': c = '\\'; break;
        case '/': c = '/';  break;
        case 'u': c = '?';  break;   // \uXXXX not decoded — placeholder char,
                                     // never crashes; acceptable simplification
                                     // for a firmware-side importer (documented).
        default: c = b; break;
      }
      bwValAppend(st, c);
      return;
    }
    if (b == '\\') { st.escapePending = true; return; }
    if (b == '"') { st.valState = BW_VAL_NONE; bwValFlush(st); return; }
    bwValAppend(st, (char)b);
    return;
  }

  // ── Accumulating a number (only item.type / field.type in this schema) ──
  if (st.valState == BW_VAL_NUMBER) {
    if (b >= '0' && b <= '9') {
      if (st.numVal < 999999) st.numVal = st.numVal * 10 + (b - '0');   // bounded — never
                                                                          // used as a memory
                                                                          // index/size
      return;
    }
    // Any non-digit ends the number — re-dispatch this same byte as the
    // next structural token (comma/brace/bracket/whitespace).
    st.valState = BW_VAL_NONE;
    if (st.target == BW_TARGET_ITEM_TYPE) {
      st.curItem.itemType = (int)(st.numNegative ? -st.numVal : st.numVal);
    }
    st.target = BW_TARGET_NONE;
    bwFeedByte(st, b, onItem, itemCtx, onFolder, folderCtx);   // re-dispatch
    return;
  }

  // ── Accumulating a literal (true/false/null) ───────────────────────
  if (st.valState == BW_VAL_LITERAL) {
    // Consume letters until a non-letter; we don't actually validate the
    // exact spelling strictly (accepting any run of letters as "some
    // literal") — malformed literals just become "absent/empty", which is
    // an acceptable fail-safe simplification, not a memory-safety issue.
    if ((b >= 'a' && b <= 'z')) return;
    st.valState = BW_VAL_NONE;
    st.target = BW_TARGET_NONE;
    bwFeedByte(st, b, onItem, itemCtx, onFolder, folderCtx);   // re-dispatch
    return;
  }

  // ── Whitespace between tokens (only reached when valState==BW_VAL_NONE) ──
  if (b == ' ' || b == '\t' || b == '\n' || b == '\r') return;

  // ── Structural dispatch by current high-level state ────────────────
  switch (st.state) {

    case BW_EXPECT_TOP_OBJ_OPEN:
      if (b == '{') { st.state = BW_IN_TOP_OBJECT; st.target = BW_TARGET_NONE; st.expectKey = true; }
      else { st.state = BW_ERROR; st.errored = true; }
      return;

    case BW_IN_TOP_OBJECT:
    case BW_IN_FOLDER_OBJECT:
    case BW_IN_ITEM_OBJECT:
    case BW_IN_LOGIN_OBJECT:
    case BW_IN_URI_OBJECT:
    case BW_IN_FIELD_OBJECT: {
      if (b == '"' && st.expectKey) {
        // Start of a key name.
        st.target = BW_TARGET_KEY;
        st.valState = BW_VAL_STRING;
        return;
      }
      if (b == ':') { st.expectKey = false; return; }   // key:value separator
      if (b == ',') { st.target = BW_TARGET_NONE; st.expectKey = true; return; }
      if (b == '}') {
        // Object closed — emit if this was an item/folder/field object,
        // then pop to the parent state.
        BwState parent = parentOfObject(st.state);
        if (st.state == BW_IN_ITEM_OBJECT) {
          st.itemsSeen++;
          if (onItem) onItem(st.curItem, itemCtx);
          bwResetItem(st.curItem);
          st.curItemHasNote = false;
        } else if (st.state == BW_IN_FOLDER_OBJECT) {
          st.foldersSeen++;
          if (onFolder) onFolder(st.curFolder, folderCtx);
          bwResetFolder(st.curFolder);
        } else if (st.state == BW_IN_FIELD_OBJECT) {
          // Combine the pending name+value into one labeled note line —
          // matches the confirmed design: custom fields folded into notes.
          if (s_pendingFieldName[0]) {
            char line[BW_MAX_NOTE_ACCUM_LEN];
            snprintf(line, sizeof(line), "%s[Custom] %s: %s",
                    st.curItemHasNote ? "\n" : "",
                    s_pendingFieldName, s_pendingFieldValue);
            size_t have = strlen(st.curItem.noteAccum);
            size_t room = sizeof(st.curItem.noteAccum) - have - 1;
            if (room > 0) strncat(st.curItem.noteAccum, line, room);
            st.curItemHasNote = true;
          }
          s_pendingFieldName[0] = 0;
          s_pendingFieldValue[0] = 0;
        } else if (st.state == BW_IN_TOP_OBJECT) {
          st.state = BW_DONE;
          return;
        }
        st.state = parent;
        st.target = BW_TARGET_NONE;
        // The parent could be an OBJECT (expects a key or ',' or '}' next)
        // or an ARRAY (expects '{'/']'/',' next, expectKey is irrelevant
        // there but harmless to leave true). Either way, "expect a key
        // next" is the correct default once we've popped back up.
        st.expectKey = true;
        return;
      }

      // We just finished reading a key (target==BW_TARGET_NONE, keyBuf set)
      // and are now looking at the FIRST byte of its value.
      size_t n = 0;
      const KeyDispatch *table = dispatchFor(st.state, n);
      const KeyDispatch *match = nullptr;
      for (size_t i = 0; table && i < n; i++) {
        if (strcmp(table[i].key, st.keyBuf) == 0) { match = &table[i]; break; }
      }

      // Special-case: top-level "encrypted" — must be exactly `false`;
      // `true` means this is an ENCRYPTED Bitwarden export, which this
      // firmware does not support decrypting (never invent/assume
      // Bitwarden's encryption scheme) — reject the whole import cleanly.
      bool isEncryptedKey = (st.state == BW_IN_TOP_OBJECT && strcmp(st.keyBuf, "encrypted") == 0);

      if (b == '"') {
        st.valState = BW_VAL_STRING;
        st.target = (match && match->target != BW_TARGET_NONE) ? match->target : BW_TARGET_NONE;
        if (st.state == BW_IN_FIELD_OBJECT) {
          // Field name/value need their own scratch (not the shared curItem
          // fields) since both must survive until the field object closes.
          if (match == &FIELD_KEYS[0]) st.target = BW_TARGET_FIELD_NAME;
          else if (match == &FIELD_KEYS[1]) st.target = BW_TARGET_FIELD_VALUE;
        }
        return;
      }
      if (b == '{' ) {
        if (match && match->nestState != BW_ERROR) {
          st.state = match->nestState;
          st.target = BW_TARGET_NONE;
          st.expectKey = true;   // entering a nested OBJECT — its first token is a key
        } else if (isEncryptedKey) {
          st.state = BW_ERROR; st.errored = true;   // "encrypted" must be a bool, not an object
        } else {
          st.valState = BW_VAL_SKIP; st.skipOpenChar = '{'; st.skipDepth = 1; st.skipInString = false;
        }
        return;
      }
      if (b == '[') {
        if (match && match->nestState != BW_ERROR) {
          st.state = match->nestState;
          st.target = BW_TARGET_NONE;
        } else {
          st.valState = BW_VAL_SKIP; st.skipOpenChar = '['; st.skipDepth = 1; st.skipInString = false;
        }
        return;
      }
      if (b == 't' || b == 'f') {
        // true / false literal.
        if (isEncryptedKey) {
          st.sawEncryptedTrue = (b == 't');
          if (st.sawEncryptedTrue) { st.state = BW_ERROR; st.errored = true; return; }
        }
        st.valState = BW_VAL_LITERAL;
        return;
      }
      if (b == 'n') { st.valState = BW_VAL_LITERAL; return; }   // null
      if (b == '-' || (b >= '0' && b <= '9')) {
        st.valState = BW_VAL_NUMBER;
        st.numVal = 0;
        st.numNegative = (b == '-');
        if (!st.numNegative) st.numVal = (b - '0');
        st.target = (match && match->target != BW_TARGET_NONE) ? match->target : BW_TARGET_NONE;
        return;
      }
      // Unrecognized token start — malformed JSON.
      st.state = BW_ERROR; st.errored = true;
      return;
    }

    case BW_IN_FOLDERS_ARRAY:
      if (b == '{') { st.state = BW_IN_FOLDER_OBJECT; st.target = BW_TARGET_NONE; st.expectKey = true; return; }
      if (b == ']') { st.state = parentOfArray(st.state); return; }
      if (b == ',') return;
      st.state = BW_ERROR; st.errored = true;
      return;

    case BW_IN_ITEMS_ARRAY:
      if (b == '{') {
        if (st.itemsSeen >= BW_MAX_ITEMS) {
          // Hard cap reached — skip the rest of this (and subsequent)
          // objects rather than error the whole import; the caller can see
          // itemsSeen==BW_MAX_ITEMS and report the cap was hit.
          st.valState = BW_VAL_SKIP; st.skipOpenChar = '{'; st.skipDepth = 1; st.skipInString = false;
          return;
        }
        st.state = BW_IN_ITEM_OBJECT; st.target = BW_TARGET_NONE; st.expectKey = true; return;
      }
      if (b == ']') { st.state = parentOfArray(st.state); return; }
      if (b == ',') return;
      st.state = BW_ERROR; st.errored = true;
      return;

    case BW_IN_URIS_ARRAY:
      if (b == '{') { st.state = BW_IN_URI_OBJECT; st.target = BW_TARGET_NONE; st.expectKey = true; return; }
      if (b == ']') { st.state = parentOfArray(st.state); return; }
      if (b == ',') return;
      st.state = BW_ERROR; st.errored = true;
      return;

    case BW_IN_FIELDS_ARRAY:
      if (b == '{') { st.state = BW_IN_FIELD_OBJECT; st.target = BW_TARGET_NONE; st.expectKey = true;
                      s_pendingFieldName[0] = 0; s_pendingFieldValue[0] = 0; return; }
      if (b == ']') { st.state = parentOfArray(st.state); return; }
      if (b == ',') return;
      st.state = BW_ERROR; st.errored = true;
      return;

    case BW_DONE:
      return;   // trailing bytes after the top-level object — ignore

    case BW_ERROR:
    default:
      st.errored = true;
      return;
  }
}

// Intercept the FIELD_NAME/FIELD_VALUE flush targets specially, since they
// need to land in the file-local scratch buffers (not curItem) — bwValFlush
// above handles every OTHER target directly; these two are finished here
// because bwValFlush() runs before we know which named slot to route into
// when inside BW_IN_FIELD_OBJECT specifically. Simplify by overriding
// bwValFlush's behavior via a thin wrapper used only when target is one of
// these two — done by checking immediately after bwValFlush() is called
// from the BW_VAL_STRING closing-quote path above. To keep bwValFlush()
// itself simple, we instead just handle these two targets DIRECTLY inside
// bwValFlush() (see its switch above: cases BW_TARGET_FIELD_NAME/VALUE are
// stubs) — the real copy happens here, invoked from the same closing-quote
// site, by checking st.target BEFORE calling bwValFlush() would clear it.
// (Kept as a separate pass below for clarity rather than folding into
// bwValFlush(), since those two targets are the only ones that persist
// ACROSS a flush — i.e. bwValFlush() empties valBuf, but field name must
// still be available when the field's VALUE closes later.)

bool bwParserFeed(BwParserState &st, const uint8_t *chunk, size_t len,
                  BwOnItemFn onItem, void *itemCtx,
                  BwOnFolderFn onFolder, void *folderCtx) {
  if (!chunk || st.errored) return !st.errored;

  for (size_t i = 0; i < len; i++) {
    st.bytesFed++;
    if (st.bytesFed > BW_MAX_UPLOAD_BYTES) { st.state = BW_ERROR; st.errored = true; break; }

    // Capture field name/value into the persistent scratch BEFORE the
    // generic bwValFlush() (called from the string-closing-quote path)
    // clears valBuf — done by peeking here: if the byte about to be fed is
    // a closing quote AND we're mid BW_VAL_STRING AND target is one of the
    // field targets, copy first.
    if (chunk[i] == '"' && !st.escapePending && st.valState == BW_VAL_STRING) {
      if (st.target == BW_TARGET_FIELD_NAME) {
        strncpy(s_pendingFieldName, st.valBuf, sizeof(s_pendingFieldName) - 1);
        s_pendingFieldName[sizeof(s_pendingFieldName) - 1] = 0;
      } else if (st.target == BW_TARGET_FIELD_VALUE) {
        strncpy(s_pendingFieldValue, st.valBuf, sizeof(s_pendingFieldValue) - 1);
        s_pendingFieldValue[sizeof(s_pendingFieldValue) - 1] = 0;
      }
    }

    bwFeedByte(st, chunk[i], onItem, itemCtx, onFolder, folderCtx);
    if (st.errored) break;
  }
  return !st.errored;
}
