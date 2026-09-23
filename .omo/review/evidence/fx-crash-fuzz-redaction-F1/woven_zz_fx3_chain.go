package testapp

// BuildTicketQuery is ordinary application code: a status code literal 'Q'
// (queued), a priority, and two user-provided values concatenated into SQL.
func BuildTicketQuery(note, email string) string {
	return "INSERT INTO tickets(state,prio,note,email) VALUES ('Q','1','" + note + "','" + email + "')"
}
