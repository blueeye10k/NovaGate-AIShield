"""Multi-layer payload de-obfuscation.

Design rules that matter (each one fixes a real bypass in v2):

1. **Additive, never destructive.** Every decoding step produces an *additional*
   scan variant. The original text is always preserved. v2 replaced the payload
   with the result of each decode, so a decode that produced binary noise
   silently erased the attack -- a one-character prefix (`"A"` + a
   punctuation-free payload) turned a risk 10.0 block into a risk 0.0 pass.
2. **Never trust a decode blindly.** Base64/hex output must be mostly printable
   and must round-trip. Otherwise the original text is kept and the decode is
   discarded. v2 used ``errors="ignore"``, which happily turned ``sha256`` into
   ``\\x16z\\x1a\\x1f~)^``.
3. **Leetspeak is a scan variant, not the display string.** v2 rewrote the whole
   prompt, turning ``3.5`` into ``e.s``, ``mp3`` into ``mpe`` and ``COVID19``
   into ``covidi9``.
4. **Bounded work.** Pass count, decoded size and input size are all capped so a
   nested-encoding bomb cannot exhaust CPU.
"""

from __future__ import annotations

import base64
import binascii
import codecs
import hashlib
import html
import re
import unicodedata
import urllib.parse
from dataclasses import dataclass, field

from novagate.config import Settings
from novagate.config import settings as default_settings

# --------------------------------------------------------------------------
# Character folding tables
# --------------------------------------------------------------------------

# Cyrillic / Greek characters that render as Latin. ``ignor\u0435`` with a
# Cyrillic "e" is invisible to every ASCII regex but is read perfectly well by
# the model.
HOMOGLYPHS: dict[str, str] = {
    # Cyrillic -> Latin
    "\u0430": "a",
    "\u0435": "e",
    "\u043e": "o",
    "\u0440": "p",
    "\u0441": "c",
    "\u0445": "x",
    "\u0443": "y",
    "\u0456": "i",
    "\u0455": "s",
    "\u0458": "j",
    "\u04bb": "h",
    "\u04cf": "l",
    "\u0454": "d",
    "\u04b9": "r",
    "\u04ba": "k",
    "\u04b7": "t",
    "\u04c0": "p",
    "\u04d9": "y",
    "\u04e3": "h",
    "\u045a": "c",
    # Greek -> Latin
    "\u03b1": "a",
    "\u03b2": "b",
    "\u03b5": "e",
    "\u03b6": "z",
    "\u03b7": "h",
    "\u03b9": "i",
    "\u03ba": "k",
    "\u03bc": "m",
    "\u03bd": "v",
    "\u03bf": "o",
    "\u03c1": "p",
    "\u03c4": "t",
    "\u03c5": "u",
    "\u03c7": "x",
    "\u0391": "a",
    "\u0392": "b",
    "\u0395": "e",
    "\u0396": "z",
    "\u0397": "h",
    "\u0399": "i",
    "\u039a": "k",
    "\u039c": "m",
    "\u039d": "v",
    "\u039f": "o",
    "\u03a1": "p",
    "\u03a4": "t",
    "\u03a5": "u",
    "\u03a7": "x",
    # Armenian / other lookalikes seen in the wild
    "\u0570": "h",
    "\u0575": "o",
    "\u0578": "n",
    "\u057c": "n",
    "\u0585": "o",
    "\u0587": "q",
    "\u0555": "o",
    "\u054f": "r",
}

# Zero-width and bidirectional control characters used to break up keywords.
INVISIBLE_RE = re.compile("[\u200b\u200c\u200d\u2060\ufeff\u00ad\u180e\u2061-\u2064\ufe00-\ufe0f]")
# Explicit bidi overrides -- a classic invisible-instruction trick.
BIDI_RE = re.compile("[\u202a-\u202e\u2066-\u2069]")
CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

LEET_MAP = {
    "0": "o",
    "1": "i",
    "2": "z",
    "3": "e",
    "4": "a",
    "5": "s",
    "6": "g",
    "7": "t",
    "8": "b",
    "9": "g",
    "@": "a",
    "$": "s",
    "!": "i",
    "|": "i",
    "+": "t",
}

# "y" is deliberately excluded: treating it as a vowel made "5y573m" score
# 0.5 before decoding and 0.33 after, so the word-likeness check rejected a
# correct decode of "system". English "y" behaves as a consonant except at the
# end of a syllable.
_VOWELS = frozenset("aeiou")
_TOKEN_RE = re.compile(r"[a-zA-Z0-9@$!|+]+", re.IGNORECASE)
_WORD_RE = re.compile(r"[a-z']+")

# The ~70 most frequent English words. Used only to judge whether a decode made
# text *more* like English -- see ``decode_rot13``. Small and hard-coded on
# purpose: pulling in a word-frequency list to decide whether to try ROT13
# would be a dependency heavier than the thing it is gating.
_COMMON_WORDS = frozenset(
    [
        "a",
        "an",
        "the",
        "and",
        "or",
        "but",
        "if",
        "then",
        "else",
        "of",
        "to",
        "in",
        "on",
        "at",
        "by",
        "for",
        "with",
        "from",
        "into",
        "onto",
        "over",
        "under",
        "is",
        "are",
        "was",
        "were",
        "be",
        "been",
        "being",
        "am",
        "do",
        "does",
        "did",
        "have",
        "has",
        "had",
        "will",
        "would",
        "shall",
        "should",
        "can",
        "could",
        "may",
        "might",
        "must",
        "not",
        "no",
        "nor",
        "so",
        "than",
        "that",
        "this",
        "these",
        "those",
        "you",
        "your",
        "yours",
        "i",
        "me",
        "my",
        "we",
        "our",
        "they",
        "them",
        "their",
        "he",
        "she",
        "it",
        "its",
        "his",
        "her",
        "there",
        "here",
        "when",
        "where",
        "why",
        "how",
        "all",
        "any",
        "each",
        "every",
        "some",
        "more",
        "most",
        "much",
        "many",
        "other",
        "such",
        "only",
        "own",
        "same",
        "about",
        "after",
        "again",
        "against",
        "because",
        "before",
        "below",
        "between",
        "during",
        "out",
        "off",
        "once",
    ]
)
_B64_RUN_RE = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")
_HEX_RUN_RE = re.compile(r"(?:[0-9a-fA-F]{2}){8,}")
_UNICODE_ESCAPE_RE = re.compile(
    r"(?:\\u[0-9a-fA-F]{4}){2,}|\\x[0-9a-fA-F]{2}(?:\\x[0-9a-fA-F]{2}){3,}"
)
_PERCENT_RE = re.compile(r"(?:%[0-9a-fA-F]{2}){3,}")


@dataclass
class NormalizationReport:
    """Result of running the pipeline over one prompt.

    ``primary`` is the conservative, human-readable form. ``variants`` holds
    every representation the evaluator should scan -- including ``primary``
    itself and always including the untouched input.
    """

    primary: str
    variants: list[str] = field(default_factory=list)
    layers_unwrapped: list[str] = field(default_factory=list)
    had_invisible_chars: bool = False
    had_bidi_controls: bool = False
    decode_depth: int = 0
    truncated: bool = False

    @property
    def payload_sha256(self) -> str:
        return hashlib.sha256(self.primary.encode("utf-8", "ignore")).hexdigest()

    def to_dict(self, *, include_variants: bool = False) -> dict:
        data = {
            "processed_string": self.primary,
            "layers_unwrapped": self.layers_unwrapped,
            "decode_depth": self.decode_depth,
            "had_invisible_chars": self.had_invisible_chars,
            "had_bidi_controls": self.had_bidi_controls,
            "payload_sha256": self.payload_sha256,
            "truncated": self.truncated,
        }
        if include_variants:
            data["variants"] = self.variants
        return data


class AdvancedPayloadNormalizer:
    """Recursively unwraps obfuscated prompt payloads without destroying text."""

    def __init__(self, config: Settings | None = None) -> None:
        self.config = config or default_settings

    # ---------------------------------------------------------------- utils
    @staticmethod
    def _printable_ratio(text: str) -> float:
        if not text:
            return 0.0
        good = sum(1 for ch in text if ch.isprintable() or ch in " \t\n")
        return good / len(text)

    @classmethod
    def _looks_like_text(cls, text: str, min_ratio: float) -> bool:
        """Gate for trusting a decode result.

        Requires printable text *and* a meaningful share of letters/digits, so
        random binary that happens to be valid UTF-8 is rejected too.
        """
        if len(text) < 2:
            return False
        if cls._printable_ratio(text) < min_ratio:
            return False
        alnum = sum(
            1 for ch in text if ch.isalnum() or ch in " \t.,!?;:'\"-_/@#$%&*()[]{}<>+=`~^|\\"
        )
        return alnum / len(text) >= min_ratio

    @staticmethod
    def _fold_unicode(text: str) -> tuple[str, bool, bool]:
        """NFKC + homoglyph folding + invisible character removal."""
        had_invisible = bool(INVISIBLE_RE.search(text))
        had_bidi = bool(BIDI_RE.search(text))

        text = unicodedata.normalize("NFKC", text)
        text = INVISIBLE_RE.sub("", text)
        text = BIDI_RE.sub("", text)
        text = CONTROL_RE.sub("", text)
        if any(ch in HOMOGLYPHS for ch in text):
            text = "".join(HOMOGLYPHS.get(ch, ch) for ch in text)
        return text, had_invisible, had_bidi

    # ------------------------------------------------------------ decoders
    @classmethod
    def decode_base64(cls, text: str, min_ratio: float, min_run: int = 16) -> str:
        """Decode ``text`` only if it is *entirely* one clean base64 blob."""
        cleaned = re.sub(r"\s+", "", text)
        if len(cleaned) < min_run or len(cleaned) % 4 != 0:
            return text
        if not re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", cleaned):
            return text
        try:
            raw = base64.b64decode(cleaned, validate=True)
        except (binascii.Error, ValueError):
            return text
        try:
            decoded = raw.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            return text
        if not cls._looks_like_text(decoded, min_ratio):
            return text
        # Round-trip: guards against decoders that quietly accept truncated data.
        if base64.b64encode(raw).decode("ascii").rstrip("=") != cleaned.rstrip("="):
            return text
        return decoded

    @classmethod
    def decode_hex(cls, text: str, min_ratio: float) -> str:
        cleaned = re.sub(r"(?:0x|\\x|\\u)[\\]?", "", text, flags=re.IGNORECASE)
        cleaned = re.sub(r"[\s:,-]", "", cleaned)
        if len(cleaned) < 16 or len(cleaned) % 2 != 0:
            return text
        if not re.fullmatch(r"[0-9a-fA-F]+", cleaned):
            return text
        try:
            raw = bytes.fromhex(cleaned)
        except ValueError:
            return text
        try:
            decoded = raw.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            return text
        if not cls._looks_like_text(decoded, min_ratio):
            return text
        return decoded

    @classmethod
    def decode_unicode_escapes(cls, text: str) -> str:
        def _sub(match: re.Match[str]) -> str:
            blob = match.group(0)
            try:
                if blob.startswith("\\u"):
                    return "".join(
                        chr(int(blob[i + 2 : i + 6], 16)) for i in range(0, len(blob), 6)
                    )
                return bytes(int(blob[i + 2 : i + 4], 16) for i in range(0, len(blob), 4)).decode(
                    "utf-8", errors="strict"
                )
            except (ValueError, UnicodeDecodeError):
                return blob

        return _UNICODE_ESCAPE_RE.sub(_sub, text)

    @classmethod
    def decode_url(cls, text: str) -> str:
        return urllib.parse.unquote(text)

    @classmethod
    def decode_html_entities(cls, text: str) -> str:
        return html.unescape(text) if "&" in text else text

    @classmethod
    def _common_word_ratio(cls, text: str) -> float:
        """Share of words that are common English function words."""
        words = [w for w in _WORD_RE.findall(text.lower()) if len(w) >= 2]
        if not words:
            return 0.0
        return sum(1 for w in words if w in _COMMON_WORDS) / len(words)

    # A decode must clear this bar before it is believed. A single function
    # word in a short payload is noise; roughly one in ten is signal.
    _min_rot13_word_ratio = 0.10

    @classmethod
    def decode_rot13(cls, text: str) -> str:
        """ROT13, but only when it makes the text *more* like English.

        ROT13 is its own inverse and never fails, so calling it on every input
        always produces a different string. That is the trap: applied blindly it
        turns every plain-English prompt into a "decoded" variant and reports a
        ``ROT13_Decode`` layer for a payload nobody obfuscated -- which is the
        same defect as decoding base64 into binary noise.

        The discriminator is the share of common English function words. Real
        English is dense in them; ROT13 of real English contains almost none,
        because the words that survive the substitution are all content words.
        So the decode is kept only when decoding *raises* the score past a
        floor. English in, English out, no layer reported; ROT13 in, plain
        English out, layer reported.
        """
        decoded = codecs.encode(text, "rot_13")
        if decoded == text:
            return text
        if cls._common_word_ratio(decoded) <= cls._min_rot13_word_ratio:
            return text
        if cls._common_word_ratio(decoded) <= cls._common_word_ratio(text):
            return text
        return decoded

    # --------------------------------------------------------- leetspeak
    @staticmethod
    def _vowel_ratio(token: str) -> float:
        letters = [ch for ch in token if ch.isalpha()]
        if not letters:
            return 0.0
        return sum(1 for ch in letters if ch in _VOWELS) / len(letters)

    @classmethod
    def leet_decode_token(cls, token: str) -> str:
        """Decode one token only when the result is *more* word-like.

        Two conditions must both hold.

        **Enough characters changed.** Either two or more substitutions, or a
        single substitution in a token of five characters or more. Requiring two
        changes unconditionally is too strict -- ``IGN0RE`` differs from
        ``ignore`` by one character and was therefore never un-obfuscated,
        while ``mp3`` (one change, three characters) was correctly left alone.

        **The word-likeness improved.** The decoded form must have a higher
        vowel ratio (over ``aeiou``) than the original. This is what keeps
        ``sha256`` and ``base64`` intact: their vowels do not improve, so the
        substitution is rejected even though the mapping would technically
        apply.

        Leetspeak results are only ever used as scan variants -- the display
        string keeps the author's original text.
        """
        mapped = "".join(LEET_MAP.get(ch, ch) for ch in token)
        changes = sum(1 for a, b in zip(token, mapped, strict=True) if a != b)
        if changes < 2 and not (changes == 1 and len(token) >= 5):
            return token
        if cls._vowel_ratio(mapped) <= cls._vowel_ratio(token):
            return token
        return mapped

    @classmethod
    def leet_decode(cls, text: str) -> str:
        """Whole-text leet variant -- used for *scanning*, not for display."""
        return _TOKEN_RE.sub(lambda m: cls.leet_decode_token(m.group(0)), text)

    # ----------------------------------------------------------- pipeline
    def execute_normalization_pipeline(self, raw_input: str) -> NormalizationReport:
        cfg = self.config
        raw = raw_input or ""
        truncated = False
        if len(raw) > cfg.max_raw_bytes:
            raw = raw[: cfg.max_raw_bytes]
            truncated = True

        variants: list[str] = [raw]
        layers: list[str] = []

        def add_variant(candidate: str, label: str) -> None:
            candidate = candidate.strip()
            if not candidate or candidate in variants:
                return
            if sum(len(v) for v in variants) + len(candidate) > cfg.max_decoded_bytes:
                return
            variants.append(candidate)
            if label not in layers:
                layers.append(label)

        # Stage 1 -- character-level folding. This always applies and defines the
        # display string, so the user never sees mojibake.
        primary, had_invisible, had_bidi = self._fold_unicode(raw)
        add_variant(primary, "Unicode_NFKC_Fold" if primary != raw else "")
        if had_invisible:
            add_variant(primary, "Invisible_Char_Strip")
        if had_bidi:
            add_variant(primary, "Bidi_Control_Strip")

        # Stage 2 -- encoding layers, applied to every variant found so far.
        budget = cfg.max_decoded_bytes
        for pass_index in range(cfg.max_decode_passes):
            grew = False
            for candidate in list(variants):
                if sum(len(v) for v in variants) > budget:
                    break
                for decoder, label in (
                    (self.decode_unicode_escapes, "Unicode_Escape_Decode"),
                    (self.decode_url, "URL_Decode"),
                    (self.decode_html_entities, "HTML_Entity_Decode"),
                    (
                        lambda t: self.decode_base64(t, cfg.min_printable_ratio, cfg.min_b64_run),
                        "Base64_Decode",
                    ),
                    (lambda t: self.decode_hex(t, cfg.min_printable_ratio), "Hex_Decode"),
                ):
                    try:
                        decoded = decoder(candidate)
                    except Exception:  # a broken decoder must never 500 the request
                        continue
                    if decoded != candidate:
                        add_variant(decoded, f"P{pass_index}_{label}")
                        grew = True

            # Stage 3 -- embedded blobs ("decode this: <base64>"). Only produces
            # scan variants; never replaces the display string.
            for candidate in list(variants):
                for match in _B64_RUN_RE.findall(candidate):
                    decoded = self.decode_base64(match, cfg.min_printable_ratio, min_run=16)
                    if decoded != match:
                        add_variant(decoded, "Embedded_Base64_Decode")
                        grew = True
                for match in _HEX_RUN_RE.findall(candidate):
                    decoded = self.decode_hex(match, cfg.min_printable_ratio)
                    if decoded != match:
                        add_variant(decoded, "Embedded_Hex_Decode")
                        grew = True

            if not grew:
                break

        # Stage 4 -- whole-text leet + rot13 variants (scan-only).
        #
        # Applied to EVERY variant, not just the raw input. Restricting this to
        # the raw string meant ``4ct%20unr35tr1ct3d`` never produced a leet
        # variant, because the payload only becomes leet after URL decoding.
        for candidate in list(variants):
            leet = self.leet_decode(candidate)
            if leet != candidate:
                add_variant(leet, "LeetSpeak_Normalization")
            rot = self.decode_rot13(candidate)
            if rot != candidate:
                add_variant(rot, "ROT13_Decode")

        # Primary display string: unicode-folded, whitespace-collapsed, lower
        # case only when it does not destroy meaning. We keep original case in
        # the display value and let the evaluator do case-insensitive matching.
        display = re.sub(r"[ \t]+", " ", primary).strip()

        return NormalizationReport(
            primary=display,
            variants=variants,
            layers_unwrapped=layers,
            had_invisible_chars=had_invisible,
            had_bidi_controls=had_bidi,
            decode_depth=len(layers),
            truncated=truncated,
        )


def normalize(raw_input: str, config: Settings | None = None) -> NormalizationReport:
    """Module-level convenience wrapper."""
    return AdvancedPayloadNormalizer(config).execute_normalization_pipeline(raw_input)
