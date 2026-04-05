package helps

import (
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

// zeroWidthSpace is the Unicode zero-width space character used for obfuscation.
const zeroWidthSpace = "\u200B"

// SensitiveWordMatcher holds the compiled regex for matching sensitive words.
type SensitiveWordMatcher struct {
	regex *regexp.Regexp
}

// BuildSensitiveWordMatcher compiles a regex from the word list.
// Words are sorted by length (longest first) for proper matching.
func BuildSensitiveWordMatcher(words []string) *SensitiveWordMatcher {
	if len(words) == 0 {
		return nil
	}

	// Filter and normalize words
	var validWords []string
	for _, w := range words {
		w = strings.TrimSpace(w)
		if utf8.RuneCountInString(w) >= 2 && !strings.Contains(w, zeroWidthSpace) {
			validWords = append(validWords, w)
		}
	}

	if len(validWords) == 0 {
		return nil
	}

	// Sort by length (longest first) for proper matching
	sort.Slice(validWords, func(i, j int) bool {
		return len(validWords[i]) > len(validWords[j])
	})

	// Escape and join
	escaped := make([]string, len(validWords))
	for i, w := range validWords {
		escaped[i] = regexp.QuoteMeta(w)
	}

	pattern := "(?i)" + strings.Join(escaped, "|")
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil
	}

	return &SensitiveWordMatcher{regex: re}
}

// obfuscateWord inserts a zero-width space after the first grapheme.
func obfuscateWord(word string) string {
	if strings.Contains(word, zeroWidthSpace) {
		return word
	}

	// Get first rune
	r, size := utf8.DecodeRuneInString(word)
	if r == utf8.RuneError || size >= len(word) {
		return word
	}

	return string(r) + zeroWidthSpace + word[size:]
}

// obfuscateText replaces all sensitive words in the text.
func (m *SensitiveWordMatcher) obfuscateText(text string) string {
	if m == nil || m.regex == nil {
		return text
	}
	return m.regex.ReplaceAllStringFunc(text, obfuscateWord)
}

// ObfuscateOpts controls which parts of the payload are processed.
type ObfuscateOpts struct {
	// SkipSystemPrefix skips the first N system blocks (e.g. 2 to skip billing + agent).
	SkipSystemPrefix int
	// IncludeMessages enables obfuscation of message content (default false).
	IncludeMessages bool
}

// ObfuscateSensitiveWords processes the payload and obfuscates sensitive words.
// By default only user system blocks (after the injected prefix) are processed.
// Pass IncludeMessages=true to also process message content.
func ObfuscateSensitiveWords(payload []byte, matcher *SensitiveWordMatcher, opts ...ObfuscateOpts) []byte {
	if matcher == nil || matcher.regex == nil {
		return payload
	}

	var o ObfuscateOpts
	if len(opts) > 0 {
		o = opts[0]
	}

	// Obfuscate in system blocks (skipping injected prefix blocks)
	payload = obfuscateSystemBlocks(payload, matcher, o.SkipSystemPrefix)

	// Obfuscate in messages only when explicitly requested
	if o.IncludeMessages {
		payload = obfuscateMessages(payload, matcher)
	}

	return payload
}

// obfuscateSystemBlocks obfuscates sensitive words in system blocks.
// skipPrefix controls how many leading system blocks to skip (e.g. injected billing/agent blocks).
func obfuscateSystemBlocks(payload []byte, matcher *SensitiveWordMatcher, skipPrefix int) []byte {
	system := gjson.GetBytes(payload, "system")
	if !system.Exists() {
		return payload
	}

	if system.IsArray() {
		modified := false
		idx := 0
		system.ForEach(func(key, value gjson.Result) bool {
			defer func() { idx++ }()
			// Skip injected control blocks at the front of the system array.
			if idx < skipPrefix {
				return true
			}
			if value.Get("type").String() == "text" {
				text := value.Get("text").String()
				obfuscated := matcher.obfuscateText(text)
				if obfuscated != text {
					path := "system." + key.String() + ".text"
					payload, _ = sjson.SetBytes(payload, path, obfuscated)
					modified = true
				}
			}
			return true
		})
		if modified {
			return payload
		}
	} else if system.Type == gjson.String {
		text := system.String()
		obfuscated := matcher.obfuscateText(text)
		if obfuscated != text {
			payload, _ = sjson.SetBytes(payload, "system", obfuscated)
		}
	}

	return payload
}

// obfuscateMessages obfuscates sensitive words in message content.
func obfuscateMessages(payload []byte, matcher *SensitiveWordMatcher) []byte {
	messages := gjson.GetBytes(payload, "messages")
	if !messages.Exists() || !messages.IsArray() {
		return payload
	}

	messages.ForEach(func(msgKey, msg gjson.Result) bool {
		content := msg.Get("content")
		if !content.Exists() {
			return true
		}

		msgPath := "messages." + msgKey.String()

		if content.Type == gjson.String {
			// Simple string content
			text := content.String()
			obfuscated := matcher.obfuscateText(text)
			if obfuscated != text {
				payload, _ = sjson.SetBytes(payload, msgPath+".content", obfuscated)
			}
		} else if content.IsArray() {
			// Array of content blocks
			content.ForEach(func(blockKey, block gjson.Result) bool {
				if block.Get("type").String() == "text" {
					text := block.Get("text").String()
					obfuscated := matcher.obfuscateText(text)
					if obfuscated != text {
						path := msgPath + ".content." + blockKey.String() + ".text"
						payload, _ = sjson.SetBytes(payload, path, obfuscated)
					}
				}
				return true
			})
		}

		return true
	})

	return payload
}
