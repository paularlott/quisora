// Package mailtpl renders the emails the server sends from a set of templates (model.EmailTemplateSet): a layout,
// which holds the header and footer of every email and places its body with {{template "body" .}}, and each email's
// subject and bodies, in HTML and in plain text.
//
// The templates are Go templates (html/template for HTML, text/template for the rest) over Data. Organizations' own
// templates are written by their administrators, so what a template may do is narrowed (Check): no loops, no templates
// of its own, no variables, no functions but tests, a bounded size and output; a link email must show its link, the
// sign-in code email its code, and no subject may show either (subjects show in lock-screen previews and
// notifications); in HTML the link shows only as a link's address or as text, and the code only as text (Render).
package mailtpl

import (
	"bytes"
	"errors"
	"fmt"
	htmltemplate "html/template"
	"io"
	"regexp"
	"slices"
	"strings"
	texttemplate "text/template"
	"text/template/parse"

	"golang.org/x/net/html"

	"github.com/paularlott/quisora/internal/model"
)

// The emails, by name (the keys of model.EmailTemplateSet.Emails).
const (
	Invite   = "invite"
	Reset    = "reset"
	Verify   = "verify"
	Recovery = "recovery"
	Code     = "code"
)

// Email describes one of the emails, for the console.
type Email struct {
	Name  string `json:"name"`
	Title string `json:"title"`
	About string `json:"about"`
	// Needs is the field the email's bodies must show ("" for none): the link it carries, or the sign-in code.
	Needs string `json:"needs,omitempty"`
}

// Emails are the emails the server sends, in the order the console shows them.
var Emails = []Email{
	{Invite, "Invitation", "Sent when an administrator invites someone: its link sets up their account.", "Link"},
	{Reset, "Password reset", "Sent when someone asks to reset their password: its link chooses a new one.", "Link"},
	{Verify, "Address verification", "Sent to confirm an email address: opening its link verifies the address.", "Link"},
	{Recovery, "Recovery code used", "Sent when a recovery code was used to sign in, with how many are left. Its link opens the account page.", ""},
	{Code, "Sign-in code", "Sent when a sign-in asks for a code by email as its second factor.", "Code"},
}

// Names are the emails' names, in the order of Emails.
func Names() []string {
	out := make([]string, len(Emails))
	for i, e := range Emails {
		out[i] = e.Name
	}
	return out
}

func lookup(name string) (Email, bool) {
	for _, e := range Emails {
		if e.Name == name {
			return e, true
		}
	}
	return Email{}, false
}

// Data is what the templates are given.
type Data struct {
	Site         string // who the email is from: the organization's display name, else the server's site name
	Org          string // the organization's display name
	Name         string // the recipient's full name
	Link         string // the link the email carries (not in the sign-in code email)
	Expires      string // how long the link or code works, such as "1 hour"
	Left         string // recovery codes left (the recovery code email)
	Code         string // the sign-in code (the sign-in code email)
	LogoURL      string // the absolute URL of the organization's logo, else of the server's
	PrimaryColor string // the organization's primary colour (#rrggbb), else the built-in one
}

// DefaultColor is Data.PrimaryColor for an organization without a colour of its own: the built-in emails' accent.
const DefaultColor = "#3730a3"

// Message is a rendered email.
type Message struct {
	Subject string `json:"subject"`
	Text    string `json:"text"`
	HTML    string `json:"html"`
}

// Limits of a template set: the longest part, the longest set, the longest rendered body and subject. A template that
// writes more fails to render.
const (
	MaxPartBytes    = 64 << 10
	MaxSetBytes     = 512 << 10
	MaxOutputBytes  = 512 << 10
	MaxSubjectRunes = 200
)

// Error is a template that cannot be used: Field names the part ("layout_html", "emails.reset.subject", ...).
type Error struct {
	Field string
	Msg   string
}

func (e *Error) Error() string { return e.Field + ": " + e.Msg }

// Merge returns the set made of the first non-empty value of each part in sets, in order: an organization's own
// templates over the primary organization's over Builtin. Unknown emails are left out.
func Merge(sets ...*model.EmailTemplateSet) model.EmailTemplateSet {
	out := model.EmailTemplateSet{Emails: map[string]model.EmailTemplate{}}
	first := func(get func(*model.EmailTemplateSet) string) string {
		for _, s := range sets {
			if s != nil {
				if v := get(s); strings.TrimSpace(v) != "" {
					return v
				}
			}
		}
		return ""
	}
	out.LayoutHTML = first(func(s *model.EmailTemplateSet) string { return s.LayoutHTML })
	out.LayoutText = first(func(s *model.EmailTemplateSet) string { return s.LayoutText })
	for _, n := range Names() {
		e := model.EmailTemplate{
			Subject: first(func(s *model.EmailTemplateSet) string { return s.Emails[n].Subject }),
			HTML:    first(func(s *model.EmailTemplateSet) string { return s.Emails[n].HTML }),
			Text:    first(func(s *model.EmailTemplateSet) string { return s.Emails[n].Text }),
		}
		if e != (model.EmailTemplate{}) {
			out.Emails[n] = e
		}
	}
	return out
}

// Normalize returns s as it is stored: line ends as \n, a part that is only white space or the same as in inherited
// left empty (it follows inherited when that changes), and no emails without a part. An unknown email is an Error.
func Normalize(s model.EmailTemplateSet, inherited model.EmailTemplateSet) (model.EmailTemplateSet, error) {
	clean := func(v, was string) string {
		v = strings.ReplaceAll(v, "\r\n", "\n")
		if strings.TrimSpace(v) == "" || v == was {
			return ""
		}
		return v
	}
	out := model.EmailTemplateSet{LayoutHTML: clean(s.LayoutHTML, inherited.LayoutHTML), LayoutText: clean(s.LayoutText, inherited.LayoutText)}
	for n, e := range s.Emails {
		if _, ok := lookup(n); !ok {
			return model.EmailTemplateSet{}, &Error{"emails." + n, "there is no such email"}
		}
		was := inherited.Emails[n]
		e = model.EmailTemplate{Subject: clean(e.Subject, was.Subject), HTML: clean(e.HTML, was.HTML), Text: clean(e.Text, was.Text)}
		if e != (model.EmailTemplate{}) {
			if out.Emails == nil {
				out.Emails = map[string]model.EmailTemplate{}
			}
			out.Emails[n] = e
		}
	}
	return out, nil
}

// IsEmpty reports whether s sets no part.
func IsEmpty(s model.EmailTemplateSet) bool {
	return s.LayoutHTML == "" && s.LayoutText == "" && len(s.Emails) == 0
}

// part is one template of a set, with the field that names it.
type part struct {
	field, src string
	layout     bool // a layout: it must place the body
	subject    bool
}

func parts(s model.EmailTemplateSet) []part {
	out := []part{{"layout_html", s.LayoutHTML, true, false}, {"layout_text", s.LayoutText, true, false}}
	for _, n := range Names() {
		e := s.Emails[n]
		out = append(out, part{"emails." + n + ".subject", e.Subject, false, true},
			part{"emails." + n + ".html", e.HTML, false, false}, part{"emails." + n + ".text", e.Text, false, false})
	}
	return out
}

// Check refuses own, an organization's templates, unless every part it sets parses and keeps to the rules, and every
// email renders, with own over inherited (what the organization would send), and shows what it must. The first
// problem found is returned as an *Error.
func Check(own, inherited model.EmailTemplateSet) error {
	total := 0
	for _, p := range parts(own) {
		if p.src == "" {
			continue
		}
		total += len(p.src)
		if len(p.src) > MaxPartBytes {
			return &Error{p.field, fmt.Sprintf("longer than %d KB", MaxPartBytes>>10)}
		}
		if err := checkSource(p); err != nil {
			return &Error{p.field, err.Error()}
		}
	}
	if total > MaxSetBytes {
		return &Error{"emails", fmt.Sprintf("the templates are longer than %d KB together", MaxSetBytes>>10)}
	}
	set := Merge(&own, &inherited)
	for _, e := range Emails {
		d := checkData(e.Name)
		msg, err := Render(set, e.Name, d)
		if err != nil {
			var te *Error
			if errors.As(err, &te) {
				return te
			}
			return err
		}
		// The subject is rendered without the link and the code: if they would show, say so rather than drop them.
		if sub, err := renderSubject(set.Emails[e.Name].Subject, d); err == nil && (d.Link != "" && strings.Contains(sub, d.Link) || d.Code != "" && strings.Contains(sub, d.Code)) {
			return &Error{"emails." + e.Name + ".subject", "must not show the link or the code: subjects show in lock-screen " +
				"previews and notifications"}
		}
		switch e.Needs {
		case "Link":
			if !strings.Contains(msg.HTML, d.Link) {
				return &Error{bodyField(own, e.Name, "html"), "must show the link: {{.Link}}"}
			}
			if !strings.Contains(msg.Text, d.Link) {
				return &Error{bodyField(own, e.Name, "text"), "must show the link: {{.Link}}"}
			}
		case "Code":
			if !strings.Contains(msg.HTML, d.Code) {
				return &Error{bodyField(own, e.Name, "html"), "must show the code: {{.Code}}"}
			}
			if !strings.Contains(msg.Text, d.Code) {
				return &Error{bodyField(own, e.Name, "text"), "must show the code: {{.Code}}"}
			}
		}
	}
	return nil
}

// bodyField names the part to blame for what a body lacks: the organization's own body, else its own layout (which
// may have left the body out), else the body.
func bodyField(own model.EmailTemplateSet, name, kind string) string {
	if kind == "html" && own.Emails[name].HTML == "" && own.LayoutHTML != "" {
		return "layout_html"
	}
	if kind == "text" && own.Emails[name].Text == "" && own.LayoutText != "" {
		return "layout_text"
	}
	return "emails." + name + "." + kind
}

// checkData is the data Check renders with: values with no characters any escaping changes, so they are found in the
// output as they are.
func checkData(name string) Data {
	d := Sample(name, Data{Site: "Example", Org: "Example", LogoURL: "https://id.example.com/branding/logo-light", PrimaryColor: DefaultColor})
	if d.Link != "" {
		d.Link = "https://id.example.com/check-link-7f3a91c2"
	}
	if d.Code != "" {
		d.Code = "418093"
	}
	return d
}

// Sample fills d, which says who the email is from, with made-up values for the email name, for previews: a link
// (unless d has one), a recipient, how long it works.
func Sample(name string, d Data) Data {
	d.Name = "Alex Example"
	switch name {
	case Invite:
		d.Expires = "7 days"
	case Reset:
		d.Expires = "1 hour"
	case Verify:
		d.Expires = "1 day"
	case Recovery:
		d.Left = "7"
	case Code:
		d.Expires = "10 minutes"
		d.Code = "123456"
		d.Link = ""
		return d
	}
	if d.Link == "" {
		d.Link = "https://id.example.com/preview-only"
	}
	return d
}

// Render renders the email name of set, which must have every part (Merge it over Builtin).
func Render(set model.EmailTemplateSet, name string, d Data) (Message, error) {
	if _, ok := lookup(name); !ok {
		return Message{}, fmt.Errorf("mailtpl: no email %q", name)
	}
	e := set.Emails[name]
	f := "emails." + name + "."
	sub, err := renderSubject(e.Subject, Data{Site: d.Site, Org: d.Org, Name: d.Name, Expires: d.Expires, Left: d.Left,
		LogoURL: d.LogoURL, PrimaryColor: d.PrimaryColor}) // never the link or the code
	if err != nil {
		return Message{}, &Error{f + "subject", explain(err)}
	}
	txt, err := renderText(set.LayoutText, e.Text, d)
	if err != nil {
		return Message{}, blame(err, "layout_text", f+"text")
	}
	htm, err := renderHTML(set.LayoutHTML, e.HTML, d)
	if err != nil {
		return Message{}, blame(err, "layout_html", f+"html")
	}
	if !secretsPlaced(set.LayoutHTML, e.HTML, d, htm) {
		field := f + "html"
		if l, err := renderHTML(set.LayoutHTML, "", d); err == nil && !secretsPlaced(set.LayoutHTML, "", d, l) {
			field = "layout_html"
		}
		return Message{}, &Error{field, misplaced}
	}
	return Message{Subject: sub, Text: txt, HTML: htm}, nil
}

const misplaced = `must show {{.Link}} only as the whole address of a link (<a href="{{.Link}}">) or as text, and ` +
	`{{.Code}} only as text: not in an image's address, a style or any other attribute, which a mail client fetches ` +
	`or could send on`

// secretsPlaced reports whether out, the HTML rendered from layout and body with d, shows d's link and code only where
// they stay with the recipient: the link as the whole href of an <a> (only the recipient's click takes it, and only
// to itself) or as text, the code only as text. Templates are written by administrators, and the primary
// organization's are every organization's: a link or code in an image's address would be fetched by the mail client,
// and sent to whoever wrote the template, with each email.
//
// The HTML is rendered again with other values for the link and the code, and the two are compared token by token:
// only text, and the href of an <a> that is the whole link, may differ. Whatever else depends on them, however it is
// escaped (a query parameter, a style, a branch on the code's value), differs, and is refused. It runs on every
// render, with the real values when an email is sent, so a branch Check did not take is caught all the same.
func secretsPlaced(layout, body string, d Data, out string) bool {
	if d.Link == "" && d.Code == "" {
		return true
	}
	alt := d
	alt.Link = other(d.Link, "https://link-check.invalid/a", "https://link-check.invalid/b")
	alt.Code = other(d.Code, "000000", "111111")
	altOut, err := renderHTML(layout, body, alt)
	if err != nil {
		return false
	}
	a, b := html.NewTokenizer(strings.NewReader(out)), html.NewTokenizer(strings.NewReader(altOut))
	raw := false // the token is the content of a raw-text element (<style>, <script>, <title>...), not text
	for {
		ta, tb := a.Next(), b.Next()
		if ta != tb {
			return false
		}
		if ta == html.ErrorToken {
			return a.Err() == io.EOF && b.Err() == io.EOF
		}
		x, y := a.Token(), b.Token()
		switch ta {
		case html.TextToken:
			if raw && x.Data != y.Data {
				return false
			}
		case html.StartTagToken, html.SelfClosingTagToken, html.EndTagToken:
			if x.Data != y.Data || len(x.Attr) != len(y.Attr) {
				return false
			}
			link := false // an <a> whose href is the link
			for i, v := range x.Attr {
				w := y.Attr[i]
				if v.Namespace != w.Namespace || v.Key != w.Key {
					return false
				}
				if v.Val != w.Val {
					if x.Data != "a" || v.Key != "href" || v.Val != d.Link || w.Val != alt.Link {
						return false
					}
					link = true
				}
			}
			if link && slices.ContainsFunc(x.Attr, func(v html.Attribute) bool { return v.Key == "ping" }) {
				return false // a click would post the link's address to the ping's
			}
		default:
			if x.Data != y.Data {
				return false
			}
		}
		raw = ta == html.StartTagToken && rawText[x.Data]
	}
}

// rawText are the elements whose content the tokenizer gives as one text token, unparsed.
var rawText = map[string]bool{"iframe": true, "noembed": true, "noframes": true, "noscript": true, "plaintext": true,
	"script": true, "style": true, "textarea": true, "title": true, "xmp": true}

// other returns a value unlike s to render with in its place ("" for none): a, else b.
func other(s, a, b string) string {
	switch s {
	case "":
		return ""
	case a:
		return b
	}
	return a
}

func renderSubject(src string, d Data) (string, error) {
	t, err := texttemplate.New("subject").Parse(src)
	if err != nil {
		return "", err
	}
	if err := allowed(t.Tree, false); err != nil {
		return "", err
	}
	w := &capped{max: MaxOutputBytes}
	if err := t.Execute(w, d); err != nil {
		return "", err
	}
	s := strings.Join(strings.Fields(w.String()), " ") // one line: no header can be added through it
	if r := []rune(s); len(r) > MaxSubjectRunes {
		s = string(r[:MaxSubjectRunes])
	}
	return s, nil
}

func renderText(layout, body string, d Data) (string, error) {
	t, err := texttemplate.New("layout").Parse(layout)
	if err != nil {
		return "", err
	}
	if _, err = t.New("body").Parse(body); err != nil {
		return "", err
	}
	var trees []*parse.Tree
	for _, x := range t.Templates() {
		trees = append(trees, x.Tree)
	}
	if err := allowedAll(trees); err != nil {
		return "", err
	}
	w := &capped{max: MaxOutputBytes}
	if err := t.ExecuteTemplate(w, "layout", d); err != nil {
		return "", err
	}
	return w.String(), nil
}

func renderHTML(layout, body string, d Data) (string, error) {
	t, err := htmltemplate.New("layout").Parse(layout)
	if err != nil {
		return "", err
	}
	if _, err = t.New("body").Parse(body); err != nil {
		return "", err
	}
	var trees []*parse.Tree
	for _, x := range t.Templates() {
		trees = append(trees, x.Tree)
	}
	if err := allowedAll(trees); err != nil {
		return "", err
	}
	w := &capped{max: MaxOutputBytes}
	if err := t.ExecuteTemplate(w, "layout", d); err != nil {
		return "", err
	}
	return w.String(), nil
}

// checkSource parses one part alone and checks it keeps to the rules (allowed), so a mistake is pinned on the part
// that has it.
func checkSource(p part) error {
	var tree *parse.Tree
	var n int
	if p.subject || strings.HasSuffix(p.field, "text") {
		t, err := texttemplate.New(name(p)).Parse(p.src)
		if err != nil {
			return errors.New(explain(err))
		}
		tree, n = t.Tree, len(t.Templates())
	} else {
		t, err := htmltemplate.New(name(p)).Parse(p.src)
		if err != nil {
			return errors.New(explain(err))
		}
		tree, n = t.Tree, len(t.Templates())
	}
	if n > 1 {
		return errors.New(`templates of its own ({{define}}, {{block}}) are not available`)
	}
	if err := allowed(tree, p.layout); err != nil {
		return err
	}
	if p.layout && !placesBody(tree.Root) {
		return errors.New(`must place the email's body with {{template "body" .}}`)
	}
	return nil
}

func name(p part) string {
	if p.layout {
		return "layout"
	}
	if p.subject {
		return "subject"
	}
	return "body"
}

// allowedAll checks the layout and the body parsed together: just those two templates, each keeping to the rules.
func allowedAll(ts []*parse.Tree) error {
	for _, t := range ts {
		if t == nil {
			continue
		}
		if t.ParseName != t.Name || len(ts) != 2 { // a {{define}} or {{block}} in one of them
			return &execNameErr{t.ParseName, errors.New(`templates of its own ({{define}}, {{block}}) are not available`)}
		}
		if err := allowed(t, t.Name == "layout"); err != nil {
			return &execNameErr{t.Name, err}
		}
	}
	return nil
}

type execNameErr struct {
	name string
	err  error
}

func (e *execNameErr) Error() string { return e.err.Error() }

// funcs are the functions a template may call: tests for {{if}}, which give true or false. No other is: print and
// printf, with a variable to feed back into ({{$a = print $a $a}}) or a width ({{printf "%999999s" ""}}), build
// strings far larger than the template, in memory, before the capped output sees any of it.
var funcs = map[string]bool{"and": true, "or": true, "not": true, "eq": true, "ne": true, "lt": true, "le": true, "gt": true, "ge": true}

// funcList names funcs for an error message, in the order Go documents them.
const funcList = "and, or, not, eq, ne, lt, le, gt, ge"

// allowed checks that a template uses no loop (the data has nothing to loop over, and {{range 1000000000}} would
// only spend the server's time), no variable of its own and no function but funcs (either could build a string of
// any size: the template must only show the fields), and places no template but, in a layout, the body.
func allowed(t *parse.Tree, layout bool) error {
	if t == nil {
		return nil
	}
	var bad error
	walk(t.Root, func(n parse.Node) {
		if bad != nil {
			return
		}
		switch n := n.(type) {
		case *parse.RangeNode:
			bad = errors.New("loops ({{range}}) are not available")
		case *parse.TemplateNode:
			if !layout || n.Name != "body" {
				bad = fmt.Errorf(`{{template %q}} is not available: only a layout places a template, the body`, n.Name)
			}
		case *parse.PipeNode:
			if len(n.Decl) > 0 {
				bad = errors.New("variables ({{$x := ...}}, {{$x = ...}}) are not available")
			}
		case *parse.IdentifierNode:
			if !funcs[n.Ident] {
				bad = fmt.Errorf("{{%s}} is not available: a template calls no function but %s", n.Ident, funcList)
			}
		}
	})
	return bad
}

func placesBody(root parse.Node) bool {
	found := false
	walk(root, func(n parse.Node) {
		if t, ok := n.(*parse.TemplateNode); ok && t.Name == "body" {
			found = true
		}
	})
	return found
}

// walk calls f on n and on every node under it, the pipelines of actions, conditions and arguments included.
func walk(n parse.Node, f func(parse.Node)) {
	if n == nil {
		return
	}
	f(n)
	switch n := n.(type) {
	case *parse.ListNode:
		if n != nil {
			for _, c := range n.Nodes {
				walk(c, f)
			}
		}
	case *parse.ActionNode:
		walk(n.Pipe, f)
	case *parse.IfNode:
		walkBranch(&n.BranchNode, f)
	case *parse.WithNode:
		walkBranch(&n.BranchNode, f)
	case *parse.RangeNode:
		walkBranch(&n.BranchNode, f)
	case *parse.TemplateNode:
		walk(n.Pipe, f)
	case *parse.PipeNode:
		if n != nil {
			for _, v := range n.Decl {
				walk(v, f)
			}
			for _, c := range n.Cmds {
				walk(c, f)
			}
		}
	case *parse.CommandNode:
		for _, a := range n.Args {
			walk(a, f)
		}
	case *parse.ChainNode:
		walk(n.Node, f)
	}
}

func walkBranch(b *parse.BranchNode, f func(parse.Node)) {
	walk(b.Pipe, f)
	walk(b.List, f)
	if b.ElseList != nil {
		walk(b.ElseList, f)
	}
}

// blame turns a render error into an *Error on the part that has it: the layout or the body.
func blame(err error, layoutField, bodyField string) error {
	field := bodyField
	var ne *execNameErr
	var ee texttemplate.ExecError
	var he *htmltemplate.Error
	switch {
	case errors.As(err, &ne):
		if ne.name == "layout" {
			field = layoutField
		}
	case errors.As(err, &ee):
		if ee.Name == "layout" {
			field = layoutField
		}
	case errors.As(err, &he):
		if he.Name == "layout" {
			field = layoutField
		}
	case strings.HasPrefix(err.Error(), "template: layout:"), strings.HasPrefix(err.Error(), "html/template:layout:"):
		field = layoutField
	}
	return &Error{field, explain(err)}
}

var (
	goErr     = regexp.MustCompile(`^(?:html/)?template: ?(?:\w+):(\d+)(?::\d+)?: (?:executing "\w+" at <(.+?)>: )?`)
	dataTypes = regexp.MustCompile(` in type (?:\*?mailtpl\.Data|\*?\w+\.\w+)`)
)

// explain words a Go template error for the person who wrote the template: "line 3: can't evaluate field Foo (at
// <.Foo>)".
func explain(err error) string {
	if errors.Is(err, errTooLong) {
		return fmt.Sprintf("writes more than %d KB", MaxOutputBytes>>10)
	}
	var ne *execNameErr
	if errors.As(err, &ne) {
		return ne.err.Error()
	}
	s := dataTypes.ReplaceAllString(err.Error(), "")
	if m := goErr.FindStringSubmatchIndex(s); m != nil {
		line, at, rest := s[m[2]:m[3]], "", s[m[1]:]
		if m[4] >= 0 {
			at = " (at " + s[m[4]:m[5]] + ")"
		}
		return "line " + line + ": " + rest + at
	}
	return s
}

var errTooLong = errors.New("mailtpl: output too long")

// capped is a buffer that refuses to grow past max.
type capped struct {
	bytes.Buffer
	max int
}

func (c *capped) Write(p []byte) (int, error) {
	if c.Len()+len(p) > c.max {
		return 0, errTooLong
	}
	return c.Buffer.Write(p)
}
