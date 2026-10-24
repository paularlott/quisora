package backup

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"
)

// A backup names the master keys its sealed secrets need (the trailer's Sealed list; a restore without one of them is
// refused with ErrKeyMissing), which sealedKeys can only do for the kinds and fields it knows. That knowledge is a
// copy of every place that seals a value into the store, and nothing else ties the two together: a sealed field added
// without a case there would restore fine without its key and be unopenable ever after. So this test finds the
// sealers itself — every call to Sealer.SealFor that names a binding constructor, repo-wide — and makes each prove
// that sealedKeys recognises a value sealed for it. (A binding passed as a variable, as Reseal forwards one, evades
// the scan; it only re-seals fields already covered here.)
//
// sealedBy names the field each binding seals, and so the entity sealedKeys must read it from.
var sealedBy = map[string]struct {
	kind  model.Kind
	field string
}{
	"TOTPBinding":           {model.KindUser, "TOTPSecret"},
	"PasswordBinding":       {model.KindUser, "PasswordHash"},
	"ProviderSecretBinding": {model.KindProvider, "ClientSecret"},
	"SigningKeyBinding":     {model.KindKey, "PrivateKey"},
	"GrantKeyBinding":       {model.KindGrant, "Key"},
	"refreshBinding":        {model.KindIdentity, "Refresh"},
}

// notBackedUp names bindings that seal values only short-lived state holds (KindEphemeral, which backups skip):
// nothing in a backup needs their key.
var notBackedUp = map[string]string{
	"pendingTOTPBinding": "an authenticator-app secret being set up, in a sign-in step or a session's pending slot",
}

func TestSealedKeysCoversEverySealedField(t *testing.T) {
	bindings := sealingBindings(t)
	t.Logf("sealed by %d bindings: %v", len(bindings), bindings)
	for _, b := range bindings {
		if _, ok := notBackedUp[b]; ok {
			continue
		}
		want, ok := sealedBy[b]
		if !ok {
			t.Errorf("%s seals a field sealedKeys does not know: add it here and a case in sealedKeys (backup.go), "+
				"or the backup will not name the key its secrets need", b)
			continue
		}
		e := model.NewEntity(want.kind)
		f := reflect.ValueOf(e).Elem().FieldByName(want.field)
		if !f.IsValid() || f.Kind() != reflect.String || !f.CanSet() {
			t.Fatalf("%s: %s has no settable string field %s", b, want.kind, want.field)
		}
		f.SetString("v3:testkey:" + "AAAA")
		rec, err := store.EncodeAsIs(e)
		if err != nil {
			t.Fatalf("%s: encode %s: %v", b, want.kind, err)
		}
		need := map[string]bool{}
		sealedKeys(rec, []string{"ring"}, need)
		if !need["testkey"] {
			t.Errorf("%s: sealedKeys does not read %s.%s; a backup would restore without the key it needs", b,
				want.kind, want.field)
		}
	}
}

// sealingBindings walks the repo's non-test Go files and returns the names of the binding constructors whose SealFor
// results are stored: service.TOTPBinding(id), refreshBinding(id) and the like, whatever names them at the call site.
func sealingBindings(t *testing.T) []string {
	root := filepath.Join("..", "..")
	fset := token.NewFileSet()
	found := map[string]bool{}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			if d != nil && d.IsDir() && (d.Name() == ".git" || d.Name() == "node_modules") {
				return filepath.SkipDir
			}
			return err
		}
		if filepath.Ext(path) != ".go" || len(path) > 8 && path[len(path)-8:] == "_test.go" {
			return nil
		}
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return err
		}
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || len(call.Args) == 0 {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "SealFor" {
				return true
			}
			if b, ok := call.Args[0].(*ast.CallExpr); ok { // a binding named here, not a variable
				switch name := b.Fun.(type) {
				case *ast.Ident:
					found[name.Name] = true
				case *ast.SelectorExpr:
					found[name.Sel.Name] = true
				}
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(found) == 0 {
		t.Fatal("no SealFor call sites found: the scan itself is broken (it must find the bindings of sealedFields)")
	}
	out := make([]string, 0, len(found))
	for name := range found {
		out = append(out, name)
	}
	return out
}
