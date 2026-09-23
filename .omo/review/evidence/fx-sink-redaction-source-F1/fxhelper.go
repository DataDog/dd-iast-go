package testapp

// FXBuildPasswordQuery concatenates a password into a SQL query. Used by the
// phase-3 redaction reproducer to exercise operator propagation in a normal
// (non-test) package file.
func FXBuildPasswordQuery(password string) string {
	return "SELECT 'login' WHERE pw = '" + password + "'"
}
