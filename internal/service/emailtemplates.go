package service

import (
	"context"
	"errors"
	"sort"

	"github.com/paularlott/quisora/internal/mailtpl"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"
)

// An organization's emails are rendered from its own templates (model.EmailTemplates), part by part over the primary
// organization's, which are the server's default, over the built-in ones (package mailtpl). The templates are records
// in the organization's partition, replicated like any other: a change reaches every node within the store's usual
// delay, and an email rendered meanwhile on a node that has not seen it yet is rendered from the templates before it.

// EmailTemplateView is an organization's email templates as the console edits them.
type EmailTemplateView struct {
	// Own are the parts the organization set itself ("" for a part it inherits).
	Own model.EmailTemplateSet `json:"own"`
	// Inherited is every part as the organization would send it without its own: the primary organization's over the
	// built-in ones (for the primary organization, the built-in ones).
	Inherited model.EmailTemplateSet `json:"inherited"`
	// Primary says whether the organization is the primary one, whose templates every other organization inherits.
	Primary bool `json:"primary"`
}

// EmailTemplates returns organization orgID's email templates: its administrators and the super admins, never a
// service account (the templates are a person's to change, UpdateEmailTemplates).
func (s *Service) EmailTemplates(ctx context.Context, a *Actor, orgID string) (*EmailTemplateView, error) {
	if !s.canAdminOrg(a, orgID) || a.ClientID != "" {
		return nil, ErrForbidden
	}
	own, err := s.ownEmailTemplates(ctx, orgID)
	if err != nil {
		return nil, err
	}
	inherited, primary, err := s.inheritedEmailTemplates(ctx, orgID)
	if err != nil {
		return nil, err
	}
	return &EmailTemplateView{Own: own.Set, Inherited: inherited, Primary: primary}, nil
}

// UpdateEmailTemplates replaces organization orgID's own email templates with in: a part left empty, or the same as
// the one it would inherit, is inherited (and follows the inherited one when that changes). Refused, with the part at
// fault, unless every email renders and shows what it must (mailtpl.Check). Its administrators and the super admins,
// never a service account; the primary organization's, which every other organization inherits, only the super
// admins.
func (s *Service) UpdateEmailTemplates(ctx context.Context, a *Actor, orgID string, in model.EmailTemplateSet) (*EmailTemplateView, error) {
	if !s.canAdminOrg(a, orgID) || a.ClientID != "" {
		return nil, ErrForbidden
	}
	o, err := s.Orgs.Get(ctx, orgID)
	if err != nil {
		return nil, mapStore(err)
	}
	inherited, primary, err := s.inheritedEmailTemplates(ctx, orgID)
	if err != nil {
		return nil, err
	}
	// The primary organization's templates render every organization's invitations, resets and sign-in codes that
	// have none of their own: changing them is a change to every organization, so it is a super admin's, as the
	// server's other settings are, not the primary organization's administrators'.
	if primary && !a.IsSuper() {
		return nil, ErrForbidden
	}
	set, err := checkEmailTemplates(in, inherited)
	if err != nil {
		return nil, err
	}
	rec, err := s.ownEmailTemplates(ctx, orgID)
	if err != nil {
		return nil, err
	}
	detail := emailTemplateChanges(rec.Set, set)
	if len(detail) > 0 {
		write := func() error {
			switch {
			case mailtpl.IsEmpty(set) && rec.Version != 0:
				err := s.EmailTpls.Delete(ctx, orgID)
				if errors.Is(err, store.ErrNotFound) {
					return nil
				}
				return err
			case mailtpl.IsEmpty(set):
				return nil
			case rec.Version == 0: // none yet, or one removed earlier (which an update may not replace)
				return s.EmailTpls.Create(ctx, &model.EmailTemplates{Meta: model.Meta{ID: orgID}, Set: set})
			}
			rec.Set = set
			return s.EmailTpls.Update(ctx, rec)
		}
		if err := s.audited(ctx, a, orgID, "org.email_templates", o.Name, detail, write); err != nil {
			return nil, mapStore(err)
		}
	}
	return &EmailTemplateView{Own: set, Inherited: inherited, Primary: primary}, nil
}

// PreviewEmailTemplates checks draft, organization orgID's own templates as they are being edited (not stored), as
// UpdateEmailTemplates would, and returns the set the organization would send with them, to render previews and test
// emails from. Its administrators and the super admins, never a service account.
func (s *Service) PreviewEmailTemplates(ctx context.Context, a *Actor, orgID string, draft model.EmailTemplateSet) (model.EmailTemplateSet, error) {
	if !s.canAdminOrg(a, orgID) || a.ClientID != "" {
		return model.EmailTemplateSet{}, ErrForbidden
	}
	inherited, _, err := s.inheritedEmailTemplates(ctx, orgID)
	if err != nil {
		return model.EmailTemplateSet{}, err
	}
	set, err := checkEmailTemplates(draft, inherited)
	if err != nil {
		return model.EmailTemplateSet{}, err
	}
	return mailtpl.Merge(&set, &inherited), nil
}

// SendingEmailTemplates returns the templates organization orgID sends its emails with: its own over the primary
// organization's over the built-in ones. It never fails: a set that cannot be read now is left out (logged), so an email
// that matters (a password reset, a sign-in code) still goes, in the inherited or the built-in look.
func (s *Service) SendingEmailTemplates(ctx context.Context, orgID string) model.EmailTemplateSet {
	var sets []*model.EmailTemplateSet
	primaryID, err := s.PrimaryOrgID(ctx)
	if err != nil && !errors.Is(err, ErrNotFound) {
		s.Log.Warn("email templates: the primary organization is not known now; built-in templates used", "error", err)
	}
	for _, id := range []string{orgID, primaryID} {
		if id == "" || id == orgID && len(sets) > 0 {
			continue
		}
		r, err := s.ownEmailTemplates(ctx, id)
		if err != nil {
			s.Log.Warn("email templates not read; inherited templates used", "organization", id, "error", err)
			continue
		}
		sets = append(sets, &r.Set)
	}
	b := mailtpl.Builtin()
	return mailtpl.Merge(append(sets, &b)...)
}

// ownEmailTemplates reads organization orgID's own templates (a record with Version 0 when it has none).
func (s *Service) ownEmailTemplates(ctx context.Context, orgID string) (*model.EmailTemplates, error) {
	r, err := s.EmailTpls.Get(ctx, orgID)
	if errors.Is(err, store.ErrNotFound) {
		return &model.EmailTemplates{Meta: model.Meta{ID: orgID}}, nil
	}
	if err != nil {
		return nil, mapStore(err)
	}
	return r, nil
}

// inheritedEmailTemplates returns what organization orgID inherits: the primary organization's templates over the
// built-in ones, or for the primary organization (reported) the built-in ones.
func (s *Service) inheritedEmailTemplates(ctx context.Context, orgID string) (model.EmailTemplateSet, bool, error) {
	b := mailtpl.Builtin()
	primaryID, err := s.PrimaryOrgID(ctx)
	if errors.Is(err, ErrNotFound) || primaryID == orgID {
		return b, primaryID == orgID, nil
	}
	if err != nil {
		return model.EmailTemplateSet{}, false, err
	}
	p, err := s.ownEmailTemplates(ctx, primaryID)
	if err != nil {
		return model.EmailTemplateSet{}, false, err
	}
	return mailtpl.Merge(&p.Set, &b), false, nil
}

// checkEmailTemplates normalizes in over inherited and checks it (mailtpl.Normalize, mailtpl.Check), as a field error
// on the part at fault.
func checkEmailTemplates(in, inherited model.EmailTemplateSet) (model.EmailTemplateSet, error) {
	set, err := mailtpl.Normalize(in, inherited)
	if err == nil {
		err = mailtpl.Check(set, inherited)
	}
	var te *mailtpl.Error
	if errors.As(err, &te) {
		return model.EmailTemplateSet{}, Invalid(te.Field, te.Msg)
	}
	return set, err
}

// emailTemplateChanges is the audit detail of a change from was to now: changed.<part> = "set", "changed" or
// "removed" (inherited again), for each part that changed.
func emailTemplateChanges(was, now model.EmailTemplateSet) map[string]string {
	detail := map[string]string{}
	note := func(field, a, b string) {
		switch {
		case a == b:
		case a == "":
			detail["changed."+field] = "set"
		case b == "":
			detail["changed."+field] = "removed"
		default:
			detail["changed."+field] = "changed"
		}
	}
	note("layout_html", was.LayoutHTML, now.LayoutHTML)
	note("layout_text", was.LayoutText, now.LayoutText)
	names := mailtpl.Names()
	sort.Strings(names)
	for _, n := range names {
		a, b := was.Emails[n], now.Emails[n]
		note("emails."+n+".subject", a.Subject, b.Subject)
		note("emails."+n+".html", a.HTML, b.HTML)
		note("emails."+n+".text", a.Text, b.Text)
	}
	if len(detail) == 0 {
		return nil
	}
	return detail
}
