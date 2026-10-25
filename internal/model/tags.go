package model

import (
	"regexp"
	"slices"
)

// MaxTags is the most tags one user or group may carry.
const MaxTags = 50

// MaxTagsText is the longest a record's tags can be as its queryable "tags" field: MaxTags tags of 64 characters,
// joined by spaces.
const MaxTagsText = MaxTags*64 + MaxTags - 1

// tagRe describes a tag: an identifier of letters, digits and . _ : / - (the colon separates a namespace, as in
// dept:finance), 1–64 characters, starting and ending with a letter or digit. Case is kept.
var tagRe = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9._:/-]{0,62}[A-Za-z0-9])?$`)

// ValidTag reports whether s is a valid tag.
func ValidTag(s string) bool { return tagRe.MatchString(s) }

// NormTags returns tags without duplicates, sorted. It returns nil for an empty input.
func NormTags(tags []string) []string {
	if len(tags) == 0 {
		return nil
	}
	out := slices.Clone(tags)
	slices.Sort(out)
	return slices.Compact(out)
}

// MergeTags returns the sorted union of the given tag lists.
func MergeTags(lists ...[]string) []string {
	var all []string
	for _, l := range lists {
		all = append(all, l...)
	}
	return NormTags(all)
}
