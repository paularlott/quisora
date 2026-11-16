package sqlstore

import (
	"regexp"
	"testing"

	"github.com/paularlott/quisora/internal/model"
)

// plainIdentifier is every name this store writes into the text of a statement: lower-case letters, digits and
// underscores, so no name can end its quotes, or the statement, whatever it is joined to.
var plainIdentifier = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)

// Only names written in the code reach the text of a statement: the tables (tableNames and those beside the kind
// tables), their columns (model.Schemas, partColumns) and the indexes made of both; every value is a bound argument.
// Scanners that flag the statements this package joins together (SQL injection by concatenation) are answered here: a
// name that is not a plain identifier fails this test before it can reach a database.
func TestIdentifiersArePlain(t *testing.T) {
	check := func(what, name string) {
		t.Helper()
		if !plainIdentifier.MatchString(name) {
			t.Errorf("%s %q is not a plain identifier (%s)", what, name, plainIdentifier)
		}
	}
	for _, name := range []string{uniqueTable, feedTable, schemaTable, partTable, importTable} {
		check("table", name)
	}
	for kind, name := range tableNames {
		check("table of "+string(kind), name)
	}
	for _, kind := range model.Kinds() {
		check("table of "+string(kind), tableName(kind))
		for _, f := range model.Schemas[kind].Fields {
			check("field of "+string(kind), f.Name)
		}
	}
	for _, c := range partColumns(&dialect{name: "sqlite"}) {
		check("column", c.name)
	}
}
